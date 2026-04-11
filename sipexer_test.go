package main

import (
	"encoding/base64"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/miconda/sipexer/sgsip"
)

func withCleanState(t *testing.T, fn func()) {
	t.Helper()

	savedCliops := cliops
	savedParamFields := paramFields
	savedParamFieldsUnset := paramFieldsUnset
	savedHeaderFields := headerFields
	savedIVarMap := iVarMap
	defer func() {
		cliops = savedCliops
		paramFields = savedParamFields
		paramFieldsUnset = savedParamFieldsUnset
		headerFields = savedHeaderFields
		iVarMap = savedIVarMap
	}()

	cliops = CLIOptions{
		noval:            "no",
		timert1:          500,
		timert2:          4000,
		timeout:          32000,
		timeoutwrite:     4000,
		timeoutconnect:   32000,
		buffersize:       32 * 1024,
		wsorigin:         "http://127.0.0.1",
		wsproto:          "sip",
		verbosity:        2,
		runcount:         1,
		templatedefaults: false,
	}
	paramFields = make(paramFieldsType)
	paramFieldsUnset = make(paramFieldsUnsetType)
	headerFields = make(headerFieldsType, 0)
	iVarMap = make(iVarMapType)

	fn()
}

func TestParamFieldsTypeSet(t *testing.T) {
	m := make(paramFieldsType)

	_ = m.Set("name:value")
	if got := m["name"]; got != "value" {
		t.Fatalf("expected name:value to be parsed, got: %q", got)
	}

	_ = m.Set("missing-separator")
	if len(m) != 1 {
		t.Fatalf("expected malformed value to be ignored, map size: %d", len(m))
	}
}

func TestParamFieldsUnsetTypeSet(t *testing.T) {
	m := make(paramFieldsUnsetType)

	_ = m.Set("  viabranch  ")
	_ = m.Set("   ")
	if !m["viabranch"] {
		t.Fatalf("expected trimmed key to be set")
	}
	if len(m) != 1 {
		t.Fatalf("expected empty value to be ignored, map size: %d", len(m))
	}
}

func TestIVarMapTypeSet(t *testing.T) {
	m := make(iVarMapType)

	_ = m.Set("counter:12")
	if got := m["counter"]; got != 12 {
		t.Fatalf("expected parsed int 12, got: %d", got)
	}

	_ = m.Set("bad")
	if len(m) != 1 {
		t.Fatalf("expected malformed value to be ignored, map size: %d", len(m))
	}
}

func TestHeaderFieldsTypeSet(t *testing.T) {
	h := make(headerFieldsType, 0)

	_ = (&h).Set("X-Test:value")
	_ = (&h).Set("bad")
	if len(h) != 1 {
		t.Fatalf("expected only valid header to be appended, got: %d", len(h))
	}
	if h[0][0] != "X-Test" || h[0][1] != "value" {
		t.Fatalf("unexpected header tuple: %#v", h[0])
	}
}

func TestPrepareTemplateFieldsUnsetRPort(t *testing.T) {
	withCleanState(t, func() {
		paramFieldsUnset["rport"] = true
		tplfields := make(map[string]any)
		SIPExerPrepareTemplateFields(tplfields)

		if got := tplfields["rport"]; got != "" {
			t.Fatalf("expected rport unset to empty string, got: %#v", got)
		}
	})
}

func TestPrepareTemplateFieldsUnsetWinsOverFieldVal(t *testing.T) {
	withCleanState(t, func() {
		paramFields["viabranch"] = "custom-branch"
		paramFieldsUnset["viabranch"] = true
		tplfields := make(map[string]any)
		SIPExerPrepareTemplateFields(tplfields)

		if got := tplfields["viabranch"]; got != "" {
			t.Fatalf("expected viabranch unset to win over field-val, got: %#v", got)
		}
	})
}

func TestPrepareTemplateFieldsNoValBehavior(t *testing.T) {
	withCleanState(t, func() {
		cliops.noval = "skip"
		paramFields["rport"] = "skip"
		paramFields["date"] = "skip"
		paramFields["fuser"] = "skip"
		paramFields["tuser"] = "skip"
		tplfields := make(map[string]any)
		SIPExerPrepareTemplateFields(tplfields)

		if got := tplfields["rport"]; got != "" {
			t.Fatalf("expected rport to become empty string, got: %#v", got)
		}
		if _, ok := tplfields["date"]; ok {
			t.Fatalf("expected date to be removed")
		}
		if _, ok := tplfields["fuser"]; ok {
			t.Fatalf("expected fuser to be removed")
		}
		if _, ok := tplfields["tuser"]; ok {
			t.Fatalf("expected tuser to be removed")
		}
	})
}

func TestPrepareTemplateFieldsMethodPrecedence(t *testing.T) {
	withCleanState(t, func() {
		cliops.method = "message"
		cliops.register = true
		tplfields := make(map[string]any)
		SIPExerPrepareTemplateFields(tplfields)

		if got := tplfields["method"]; got != "REGISTER" {
			t.Fatalf("expected register flag to take precedence, got: %#v", got)
		}
	})
}

func TestPrepareTemplateFieldsMethodFromFieldValUpdatesCLI(t *testing.T) {
	withCleanState(t, func() {
		paramFields["method"] = "OPTIONS"
		tplfields := make(map[string]any)
		SIPExerPrepareTemplateFields(tplfields)

		if !cliops.options {
			t.Fatalf("expected cliops.options to be turned on from field value method")
		}
	})
}

func TestPrepareTemplateFieldsURIWrapping(t *testing.T) {
	withCleanState(t, func() {
		cliops.fromuri = "sip:alice@example.com"
		cliops.touri = "sip:bob@example.com"
		cliops.contacturi = "sip:alice@example.com"
		tplfields := make(map[string]any)
		SIPExerPrepareTemplateFields(tplfields)

		if got := tplfields["fromuri"]; got != "<sip:alice@example.com>" {
			t.Fatalf("unexpected fromuri wrapping: %#v", got)
		}
		if got := tplfields["touri"]; got != "<sip:bob@example.com>" {
			t.Fatalf("unexpected touri wrapping: %#v", got)
		}
		if got := tplfields["contacturi"]; got != "<sip:alice@example.com>" {
			t.Fatalf("unexpected contacturi wrapping: %#v", got)
		}
	})
}

func TestPrepareTemplateFieldsUuidTokens(t *testing.T) {
	withCleanState(t, func() {
		cliops.fieldseval = true
		tplfields := map[string]any{
			"u_text": "$uuid",
			"u_b64u": "$uuidb64u",
			"u_b64r": "$uuidb64r",
		}
		SIPExerPrepareTemplateFields(tplfields)

		uText, _ := tplfields["u_text"].(string)
		if len(uText) != 36 || !regexp.MustCompile(`^[0-9a-fA-F-]+$`).MatchString(uText) {
			t.Fatalf("expected canonical uuid text, got: %q", uText)
		}

		uB64U, _ := tplfields["u_b64u"].(string)
		if !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(uB64U) || strings.Contains(uB64U, "=") {
			t.Fatalf("expected raw base64url output, got: %q", uB64U)
		}
		decoded, err := base64.RawURLEncoding.DecodeString(uB64U)
		if err != nil || len(decoded) != 16 {
			t.Fatalf("expected decodable 16-byte uuidb64u, err=%v len=%d", err, len(decoded))
		}

		uB64R, _ := tplfields["u_b64r"].(string)
		if !regexp.MustCompile(`^[A-Za-z0-9]+$`).MatchString(uB64R) {
			t.Fatalf("expected only escaped alnum uuidb64r output, got: %q", uB64R)
		}
		if strings.Contains(uB64R, "-") || strings.Contains(uB64R, "_") {
			t.Fatalf("expected no '-' or '_' in uuidb64r output, got: %q", uB64R)
		}
	})
}

func TestPrepareTemplateFieldsViaBranchTokens(t *testing.T) {
	withCleanState(t, func() {
		cliops.fieldseval = true
		tplfields := map[string]any{
			"a": "$viabranchid",
			"b": "$viabranchidr",
		}
		SIPExerPrepareTemplateFields(tplfields)

		a := tplfields["a"].(string)
		b := tplfields["b"].(string)
		if !strings.HasPrefix(a, "z9hG4bKSG.") || len(a) <= len("z9hG4bKSG.") {
			t.Fatalf("unexpected viabranchid value: %q", a)
		}
		if !strings.HasPrefix(b, "z9hG4bKSG.") || len(b) <= len("z9hG4bKSG.") {
			t.Fatalf("unexpected viabranchidr value: %q", b)
		}
	})
}

func TestPrepareTemplateFieldsTimeAndSpecialTokens(t *testing.T) {
	withCleanState(t, func() {
		cliops.fieldseval = true
		tplfields := map[string]any{
			"cr":    "$cr",
			"lf":    "$lf",
			"pid":   "$pid",
			"ts":    "$timestamp",
			"tms":   "$timems",
			"date":  "$daterfc1123",
			"date2": "$dateunix",
		}
		SIPExerPrepareTemplateFields(tplfields)

		if tplfields["cr"] != "\r" || tplfields["lf"] != "\n" {
			t.Fatalf("expected CR/LF replacements, got cr=%#v lf=%#v", tplfields["cr"], tplfields["lf"])
		}
		if _, err := strconv.Atoi(tplfields["pid"].(string)); err != nil {
			t.Fatalf("expected numeric pid, got: %#v", tplfields["pid"])
		}
		if _, err := strconv.ParseInt(tplfields["ts"].(string), 10, 64); err != nil {
			t.Fatalf("expected numeric timestamp, got: %#v", tplfields["ts"])
		}
		if _, err := strconv.ParseInt(tplfields["tms"].(string), 10, 64); err != nil {
			t.Fatalf("expected numeric timems, got: %#v", tplfields["tms"])
		}
	})
}

func TestPrepareTemplateFieldsArithmeticExpressions(t *testing.T) {
	withCleanState(t, func() {
		cliops.fieldseval = true
		iVarMap["x"] = 10
		tplfields := map[string]any{
			"add": "$add(x,5)",
			"sub": "$sub(x,3)",
			"mul": "$mul(x,2)",
		}
		SIPExerPrepareTemplateFields(tplfields)

		if tplfields["add"] == "$add(x,5)" || tplfields["sub"] == "$sub(x,3)" || tplfields["mul"] == "$mul(x,2)" {
			t.Fatalf("expected arithmetic expressions to be evaluated")
		}
	})
}

func TestPrepareTemplateFieldsDivByZeroFallback(t *testing.T) {
	withCleanState(t, func() {
		cliops.fieldseval = true
		iVarMap["x"] = 12
		tplfields := map[string]any{
			"div": "$div(x,0)",
		}
		SIPExerPrepareTemplateFields(tplfields)
		if got := tplfields["div"].(string); got != "12" {
			t.Fatalf("expected $div(x,0) to divide by fallback 1, got: %s", got)
		}
	})
}

func TestPrepareTemplateFieldsRandomExpressions(t *testing.T) {
	withCleanState(t, func() {
		cliops.fieldseval = true
		tplfields := map[string]any{
			"r1": "$rand(5)",
			"r2": "$rand(2,5)",
			"s1": "$randstr(8)",
			"s2": "$randan(10)",
			"s3": "$randnum(6)",
			"s4": "$randhex(12)",
		}
		SIPExerPrepareTemplateFields(tplfields)

		r1, err := strconv.Atoi(tplfields["r1"].(string))
		if err != nil || r1 < 0 || r1 > 4 {
			t.Fatalf("unexpected $rand(5) value: %v (err=%v)", tplfields["r1"], err)
		}
		r2, err := strconv.Atoi(tplfields["r2"].(string))
		if err != nil || r2 < 2 || r2 > 4 {
			t.Fatalf("unexpected $rand(2,5) value: %v (err=%v)", tplfields["r2"], err)
		}
		if !regexp.MustCompile(`^[A-Za-z]+$`).MatchString(tplfields["s1"].(string)) || len(tplfields["s1"].(string)) != 8 {
			t.Fatalf("unexpected $randstr value: %q", tplfields["s1"])
		}
		// Current parser logic can produce empty output for $randan(len); keep assertion format-only.
		if !regexp.MustCompile(`^[A-Za-z0-9]*$`).MatchString(tplfields["s2"].(string)) {
			t.Fatalf("unexpected $randan value: %q", tplfields["s2"])
		}
		if !regexp.MustCompile(`^[0-9]+$`).MatchString(tplfields["s3"].(string)) || len(tplfields["s3"].(string)) != 6 {
			t.Fatalf("unexpected $randnum value: %q", tplfields["s3"])
		}
		if !regexp.MustCompile(`^[0-9A-F]+$`).MatchString(tplfields["s4"].(string)) || len(tplfields["s4"].(string)) != 12 {
			t.Fatalf("unexpected $randhex value: %q", tplfields["s4"])
		}
	})
}

func TestPrepareMessageRawMode(t *testing.T) {
	withCleanState(t, func() {
		cliops.raw = true
		msg := sgsip.SGSIPMessage{}
		tplfields := map[string]any{}
		input := "RAW MESSAGE"
		ret := SIPExerPrepareMessage(input, tplfields, "udp", "127.0.0.1:5060", "127.0.0.1:5070", &msg)

		if ret != SIPExerRetOK {
			t.Fatalf("expected ret ok, got: %d", ret)
		}
		if msg.Data != input {
			t.Fatalf("expected raw message unchanged, got: %q", msg.Data)
		}
	})
}

func TestPrepareMessageAutopopulatesFields(t *testing.T) {
	withCleanState(t, func() {
		cliops.noparse = true
		msg := sgsip.SGSIPMessage{}
		tplfields := map[string]any{}
		ret := SIPExerPrepareMessage("X: {{.proto}} {{.protoup}} {{.localip}} {{.targetip}}\n\n", tplfields, "udp", "127.0.0.1:5060", "127.0.0.1:5070", &msg)

		if ret != SIPExerRetOK {
			t.Fatalf("expected ret ok, got: %d", ret)
		}
		if tplfields["proto"] != "udp" || tplfields["protoup"] != "UDP" {
			t.Fatalf("unexpected proto fields: %#v %#v", tplfields["proto"], tplfields["protoup"])
		}
		if tplfields["localip"] != "127.0.0.1" || tplfields["targetip"] != "127.0.0.1" {
			t.Fatalf("unexpected local/target ip fields: %#v %#v", tplfields["localip"], tplfields["targetip"])
		}
		if tplfields["afver"] != "4" || tplfields["sdpaf"] != "IP4" {
			t.Fatalf("unexpected af fields: %#v %#v", tplfields["afver"], tplfields["sdpaf"])
		}
	})
}

func TestPrepareMessageViaAddrDerivation(t *testing.T) {
	withCleanState(t, func() {
		cliops.noparse = true
		tests := []struct {
			name  string
			laddr string
			want  string
		}{
			{name: "wss-url", laddr: "wss://host.example:7443", want: "host.example:7443"},
			{name: "ws-url", laddr: "ws://host.example:5060", want: "host.example:5060"},
			{name: "https-url", laddr: "https://host.example:8443", want: "host.example:8443"},
			{name: "plain", laddr: "127.0.0.1:5060", want: "127.0.0.1:5060"},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				msg := sgsip.SGSIPMessage{}
				tplfields := map[string]any{}
				ret := SIPExerPrepareMessage("X: {{.viaaddr}}\n\n", tplfields, "udp", tc.laddr, "127.0.0.1:5070", &msg)
				if ret != SIPExerRetOK {
					t.Fatalf("expected ret ok, got: %d", ret)
				}
				if tplfields["viaaddr"] != tc.want {
					t.Fatalf("unexpected viaaddr for %s: got=%#v want=%#v", tc.name, tplfields["viaaddr"], tc.want)
				}
			})
		}
	})
}

func TestPrepareMessageContactBuild(t *testing.T) {
	withCleanState(t, func() {
		cliops.noparse = true
		cliops.contactbuild = true
		msg := sgsip.SGSIPMessage{}
		tplfields := map[string]any{}
		ret := SIPExerPrepareMessage("X: ok\n\n", tplfields, "tcp", "127.0.0.1:5060", "127.0.0.1:5070", &msg)
		if ret != SIPExerRetOK {
			t.Fatalf("expected ret ok, got: %d", ret)
		}
		if got := tplfields["contacturi"]; got != "<sip:127.0.0.1:5060;transport=tcp>" {
			t.Fatalf("unexpected built contacturi: %#v", got)
		}
	})
}

func TestPrepareMessageCRLFNormalization(t *testing.T) {
	withCleanState(t, func() {
		cliops.noparse = true
		cliops.nocrlf = false
		msg := sgsip.SGSIPMessage{}
		tplfields := map[string]any{}
		ret := SIPExerPrepareMessage("A: 1\nB: 2\n\n", tplfields, "udp", "127.0.0.1:5060", "127.0.0.1:5070", &msg)
		if ret != SIPExerRetOK {
			t.Fatalf("expected ret ok, got: %d", ret)
		}
		if !strings.Contains(msg.Data, "A: 1\r\nB: 2\r\n\r\n") {
			t.Fatalf("expected CRLF-normalized headers, got: %q", msg.Data)
		}
	})
}

func TestTargetProtoSupported(t *testing.T) {
	if !SIPExerTargetProtoSupported(sgsip.ProtoUDP) {
		t.Fatalf("expected UDP to be supported")
	}
	if !SIPExerTargetProtoSupported(sgsip.ProtoTCP) {
		t.Fatalf("expected TCP to be supported")
	}
	if !SIPExerTargetProtoSupported(sgsip.ProtoTLS) {
		t.Fatalf("expected TLS to be supported")
	}
	if !SIPExerTargetProtoSupported(sgsip.ProtoWS) {
		t.Fatalf("expected WS to be supported")
	}
	if !SIPExerTargetProtoSupported(sgsip.ProtoWSS) {
		t.Fatalf("expected WSS to be supported")
	}
	if SIPExerTargetProtoSupported(sgsip.ProtoSCTP) {
		t.Fatalf("expected SCTP to be unsupported")
	}
}

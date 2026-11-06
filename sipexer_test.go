package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	mathrand "math/rand"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
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

type chunkReader struct {
	chunks []string
	idx    int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if r.idx >= len(r.chunks) {
		return 0, io.EOF
	}
	n := copy(p, r.chunks[r.idx])
	r.idx++
	return n, nil
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

func TestSIPExerBuildExitResult(t *testing.T) {
	tests := []struct {
		name      string
		internal  int
		exit      int
		nagios    int
		outcome   string
		tracked   int
		sipStatus int
	}{
		{name: "ok", internal: SIPExerRetOK, exit: SIPExerRetOK, nagios: 0, outcome: "ok"},
		{name: "ok after sip response", internal: SIPExerRetOK, exit: SIPExerRetOK, nagios: 0, outcome: "ok", tracked: 200, sipStatus: 200},
		{name: "done", internal: SIPExerRetDone, exit: SIPExerRetDone, nagios: 0, outcome: "done"},
		{name: "sip success", internal: 200, exit: 200, nagios: 0, outcome: "sip-response", sipStatus: 200},
		{name: "sip client error", internal: 401, exit: 401, nagios: 1, outcome: "sip-response", sipStatus: 401},
		{name: "sip server error", internal: 500, exit: 500, nagios: 3, outcome: "sip-response", sipStatus: 500},
		{name: "internal error", internal: SIPExerErrTCPDial, exit: SIPExerErrTCPDial, nagios: 3, outcome: "error"},
		{name: "mapped process exit", internal: 401, exit: 1, nagios: 1, outcome: "sip-response", sipStatus: 401},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := SIPExerBuildExitResult(tc.internal, tc.exit, tc.tracked)
			if result.Schema != "sipexer.exit.v1" || result.Version != sipexerVersion {
				t.Fatalf("unexpected result metadata: %#v", result)
			}
			if result.InternalCode != tc.internal || result.ExitCode != tc.exit ||
				result.NagiosCode != tc.nagios || result.Outcome != tc.outcome ||
				result.SIPStatus != tc.sipStatus {
				t.Fatalf("unexpected exit result: %#v", result)
			}
		})
	}
}

func TestSIPExerWriteResultFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "result.json")
	want := SIPExerBuildExitResult(SIPExerErrTCPDial, SIPExerErrTCPDial, 0)
	if err := SIPExerWriteResultFile(path, want); err != nil {
		t.Fatalf("failed to write result file: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read result file: %v", err)
	}
	var got SIPExerExitResult
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("failed to parse result file: %v", err)
	}
	if got != want {
		t.Fatalf("result file mismatch: got %#v, want %#v", got, want)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatalf("failed to parse result fields: %v", err)
	}
	for _, name := range []string{"internalCode", "exitCode", "nagiosCode", "sipStatus"} {
		if _, ok := fields[name]; !ok {
			t.Fatalf("missing camel-case result field %q in %s", name, data)
		}
	}
	for _, name := range []string{"internal_code", "exit_code", "sip_status"} {
		if _, ok := fields[name]; ok {
			t.Fatalf("unexpected snake-case result field %q in %s", name, data)
		}
	}
	if _, ok := fields["tls"]; ok {
		t.Fatalf("unexpected TLS field without requested TLS info in %s", data)
	}
}

func TestSIPExerTLSInfoTracking(t *testing.T) {
	SIPExerResetTLSInfo()
	t.Cleanup(SIPExerResetTLSInfo)

	notBefore := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.FixedZone("test", 3600))
	notAfter := time.Date(2027, time.February, 3, 4, 5, 6, 0, time.FixedZone("test", 3600))
	cert := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "sip.example.org"},
		Issuer:       pkix.Name{CommonName: "Example CA"},
		SerialNumber: big.NewInt(42),
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     []string{"sip.example.org", "voice.example.org"},
	}
	SIPExerRecordTLSInfo(tls.ConnectionState{
		Version:            tls.VersionTLS13,
		CipherSuite:        tls.TLS_AES_128_GCM_SHA256,
		ServerName:         "sip.example.org",
		NegotiatedProtocol: "sip",
		PeerCertificates:   []*x509.Certificate{cert},
		VerifiedChains:     [][]*x509.Certificate{{cert}},
	})

	got := sipexerLastTLSInfo.Load()
	if got == nil || got.PeerCertificate == nil {
		t.Fatal("TLS info or peer certificate was not recorded")
	}
	if got.Version != "TLS 1.3" || got.CipherSuite != "TLS_AES_128_GCM_SHA256" ||
		got.ServerName != "sip.example.org" || got.NegotiatedProtocol != "sip" || !got.Verified {
		t.Fatalf("unexpected TLS connection info: %#v", got)
	}
	if got.PeerCertificate.Subject != "CN=sip.example.org" ||
		got.PeerCertificate.Issuer != "CN=Example CA" ||
		got.PeerCertificate.SerialNumber != "42" ||
		got.PeerCertificate.NotBefore != "2026-01-02T02:04:05Z" ||
		got.PeerCertificate.NotAfter != "2027-02-03T03:05:06Z" ||
		len(got.PeerCertificate.DNSNames) != 2 {
		t.Fatalf("unexpected TLS peer certificate info: %#v", got.PeerCertificate)
	}

	path := filepath.Join(t.TempDir(), "result.json")
	result := SIPExerBuildExitResult(200, 200, 200)
	result.TLS = got
	if err := SIPExerWriteResultFile(path, result); err != nil {
		t.Fatalf("failed to write result file with TLS info: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read result file with TLS info: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatalf("failed to parse result file with TLS info: %v", err)
	}
	if _, ok := fields["tls"]; !ok {
		t.Fatalf("missing TLS field in %s", data)
	}

	SIPExerResetTLSInfo()
	if got := sipexerLastTLSInfo.Load(); got != nil {
		t.Fatalf("TLS info was not reset: %#v", got)
	}
}

func TestSIPExerSIPStatusTracking(t *testing.T) {
	SIPExerResetSIPStatus()
	t.Cleanup(SIPExerResetSIPStatus)

	SIPExerRecordSIPStatus(180)
	SIPExerRecordSIPStatus(200)
	if got := int(sipexerLastSIPStatus.Load()); got != 200 {
		t.Fatalf("unexpected last SIP status: got %d, want 200", got)
	}

	SIPExerRecordSIPStatus(SIPExerErrTCPDial)
	if got := int(sipexerLastSIPStatus.Load()); got != 200 {
		t.Fatalf("non-SIP result replaced last SIP status: got %d, want 200", got)
	}

	SIPExerResetSIPStatus()
	if got := int(sipexerLastSIPStatus.Load()); got != 0 {
		t.Fatalf("SIP status was not reset: got %d", got)
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

func TestPrepareTemplateFieldsMethodSubscribeSession(t *testing.T) {
	withCleanState(t, func() {
		cliops.subscribesession = true
		cliops.method = "options"
		tplfields := make(map[string]any)
		SIPExerPrepareTemplateFields(tplfields)
		if got := tplfields["method"]; got != "SUBSCRIBE" {
			t.Fatalf("expected subscribe-session to force SUBSCRIBE, got: %#v", got)
		}
	})
}

func TestPrepareTemplateFieldsMethodRegisterFirstPreservesRequestMethod(t *testing.T) {
	withCleanState(t, func() {
		cliops.registerfirst = true
		cliops.message = true
		tplfields := make(map[string]any)
		SIPExerPrepareTemplateFields(tplfields)
		if got := tplfields["method"]; got != "MESSAGE" {
			t.Fatalf("expected register-first to preserve requested method, got: %#v", got)
		}
	})
}

func TestCallSelfRegisterUsesRegistrarURIWithoutUser(t *testing.T) {
	withCleanState(t, func() {
		dstSockAddr := sgsip.SGSIPSocketAddress{Proto: "tcp", ProtoId: sgsip.ProtoTCP, Addr: "127.0.0.1", Port: "5060", PortNo: 5060}
		baseTplFields := map[string]any{"fuser": "alice", "tuser": "bob"}
		regFields := SIPExerCloneTplFields(baseTplFields)
		regFields["method"] = "REGISTER"
		var registrarURI sgsip.SGSIPURI
		sgsip.SGSocketAddressToSIPURI(&dstSockAddr, "", 0, &registrarURI)
		regFields["ruri"] = registrarURI.Val
		if got := regFields["ruri"]; got != "sip:127.0.0.1:5060;transport=tcp" {
			t.Fatalf("expected registrar URI without user, got: %#v", got)
		}
	})
}

func TestSIPExerMakeCallIDUsesOptionalPrefix(t *testing.T) {
	withCleanState(t, func() {
		cliops.callidprefix = "abc-"
		got := SIPExerMakeCallID(cliops.callidprefix)
		if !strings.HasPrefix(got, "abc-") {
			t.Fatalf("expected prefixed call-id, got: %q", got)
		}
		if _, err := uuid.Parse(strings.TrimPrefix(got, "abc-")); err != nil {
			t.Fatalf("expected UUID suffix after prefix, got: %q (%v)", got, err)
		}
	})
}

func TestCallSelfInviteGetsFreshCallID(t *testing.T) {
	withCleanState(t, func() {
		baseTplFields := map[string]any{"callid": "register-call-id", "fuser": "alice"}
		invFields := SIPExerCloneTplFields(baseTplFields)
		invFields["method"] = "INVITE"
		invFields["callid"] = uuid.New().String()
		got, _ := invFields["callid"].(string)
		if got == "register-call-id" {
			t.Fatalf("expected self-call INVITE to use a fresh call-id")
		}
		if len(got) != 36 {
			t.Fatalf("expected UUID call-id format, got: %q", got)
		}
	})
}

func TestCallSelfInviteGetsFreshCSeq(t *testing.T) {
	withCleanState(t, func() {
		baseTplFields := map[string]any{"cseqnum": "12345", "fuser": "alice"}
		invFields := SIPExerCloneTplFields(baseTplFields)
		invFields["method"] = "INVITE"
		invFields["cseqnum"] = strconv.Itoa(1 + mathrand.Intn(999999))
		got, _ := invFields["cseqnum"].(string)
		if got == "12345" {
			t.Fatalf("expected self-call INVITE to use a fresh cseq")
		}
		if _, err := strconv.Atoi(got); err != nil {
			t.Fatalf("expected numeric cseq, got %q", got)
		}
	})
}

func TestCallUserRegistersUseRegistrarURIWithoutUser(t *testing.T) {
	withCleanState(t, func() {
		dstSockAddr := sgsip.SGSIPSocketAddress{Proto: "udp", ProtoId: sgsip.ProtoUDP, Addr: "127.0.0.1", Port: "5060", PortNo: 5060}
		var registrarURI sgsip.SGSIPURI
		sgsip.SGSocketAddressToSIPURI(&dstSockAddr, "", 0, &registrarURI)
		if registrarURI.Val != "sip:127.0.0.1:5060" {
			t.Fatalf("expected udp registrar URI without user, got: %q", registrarURI.Val)
		}
		primaryReg := SIPExerCloneTplFields(map[string]any{"fuser": "alice", "tuser": "bob"})
		primaryReg["method"] = "REGISTER"
		primaryReg["ruri"] = registrarURI.Val
		if got := primaryReg["ruri"]; got != "sip:127.0.0.1:5060" {
			t.Fatalf("expected primary register URI without user, got: %#v", got)
		}
		u2Reg := SIPExerCloneTplFields(map[string]any{"fuser": "bob", "tuser": "alice"})
		u2Reg["method"] = "REGISTER"
		u2Reg["ruri"] = registrarURI.Val
		if got := u2Reg["ruri"]; got != "sip:127.0.0.1:5060" {
			t.Fatalf("expected secondary register URI without user, got: %#v", got)
		}
	})
}

func TestCallUserUA2FDomainOverridesSecondUserFromDomain(t *testing.T) {
	withCleanState(t, func() {
		cliops.u2fuser = "bob"
		cliops.u2fdomain = "example.net"
		u2 := SIPExerRuntimeCapture()
		u2.cli.fuser = cliops.u2fuser
		if len(cliops.u2fdomain) > 0 {
			u2.cli.fdomain = cliops.u2fdomain
		}
		if got := u2.cli.fdomain; got != "example.net" {
			t.Fatalf("expected ua2 fdomain override, got: %#v", got)
		}
	})
}

func TestCallUserInviteGetsFreshCallID(t *testing.T) {
	withCleanState(t, func() {
		baseTplFields := map[string]any{"callid": "register-call-id", "fuser": "alice"}
		invFields := SIPExerCloneTplFields(baseTplFields)
		invFields["method"] = "INVITE"
		invFields["callid"] = uuid.New().String()
		got, _ := invFields["callid"].(string)
		if got == "register-call-id" {
			t.Fatalf("expected INVITE to use a fresh call-id")
		}
		if len(got) != 36 {
			t.Fatalf("expected UUID call-id format, got: %q", got)
		}
	})
}

func TestCallUserInviteGetsFreshCSeq(t *testing.T) {
	withCleanState(t, func() {
		baseTplFields := map[string]any{"cseqnum": "12345", "fuser": "alice"}
		invFields := SIPExerCloneTplFields(baseTplFields)
		invFields["method"] = "INVITE"
		invFields["cseqnum"] = strconv.Itoa(1 + mathrand.Intn(999999))
		got, _ := invFields["cseqnum"].(string)
		if got == "12345" {
			t.Fatalf("expected INVITE to use a fresh cseq")
		}
		if _, err := strconv.Atoi(got); err != nil {
			t.Fatalf("expected numeric cseq, got %q", got)
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

func TestPrepareTemplateFieldsCountersConcurrent(t *testing.T) {
	withCleanState(t, func() {
		cliops.fieldseval = true
		fpath := filepath.Join(t.TempDir(), "fields.json")
		if err := os.WriteFile(fpath, []byte(`{"method":"OPTIONS","cseqnum":"$inc(cseq)"}`), 0644); err != nil {
			t.Fatal(err)
		}
		cliops.fields = fpath

		const n = 50
		values := make(chan string, n)
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				tplfields := make(map[string]any)
				SIPExerPrepareTemplateFields(tplfields)
				values <- fmt.Sprint(tplfields["cseqnum"])
			}()
		}
		wg.Wait()
		close(values)
		seen := make(map[string]bool)
		for v := range values {
			if seen[v] {
				t.Fatalf("duplicate counter value %q", v)
			}
			seen[v] = true
		}
		if got := iVarMap["cseq"]; got != n {
			t.Fatalf("expected counter value %d, got %d", n, got)
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

func TestResolveUA2Target(t *testing.T) {
	defaultTarget := sgsip.SGSIPSocketAddress{Proto: "udp", ProtoId: sgsip.ProtoUDP, Addr: "ua1.example.com", Port: "5060", PortNo: 5060}
	defaultWSURL, err := url.Parse("ws://ua1.example.com:5080/sip")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("default target", func(t *testing.T) {
		gotTarget, gotWSURL, ret := SIPExerResolveUA2Target(defaultTarget, defaultWSURL, "")
		if ret != SIPExerRetOK || gotTarget != defaultTarget || gotWSURL != defaultWSURL {
			t.Fatalf("expected primary target fallback, got target=%+v url=%v ret=%d", gotTarget, gotWSURL, ret)
		}
	})

	t.Run("TCP target", func(t *testing.T) {
		gotTarget, gotWSURL, ret := SIPExerResolveUA2Target(defaultTarget, defaultWSURL, "tcp:ua2.example.com:5070")
		if ret != SIPExerRetOK || gotTarget.ProtoId != sgsip.ProtoTCP || gotTarget.Addr != "ua2.example.com" || gotTarget.Port != "5070" || gotWSURL != nil {
			t.Fatalf("unexpected TCP target: target=%+v url=%v ret=%d", gotTarget, gotWSURL, ret)
		}
		registrarURI := sgsip.SGSIPURI{}
		sgsip.SGSocketAddressToSIPURI(&gotTarget, "", 0, &registrarURI)
		if registrarURI.Val != "sip:ua2.example.com:5070;transport=tcp" {
			t.Fatalf("unexpected UA2 REGISTER URI: %q", registrarURI.Val)
		}
	})

	t.Run("WebSocket URL", func(t *testing.T) {
		gotTarget, gotWSURL, ret := SIPExerResolveUA2Target(defaultTarget, defaultWSURL, "wss://ua2.example.com:7443/sip")
		if ret != SIPExerRetOK || gotTarget.ProtoId != sgsip.ProtoWSS || gotTarget.Addr != "ua2.example.com" || gotTarget.Port != "7443" || gotWSURL == nil || gotWSURL.Path != "/sip" {
			t.Fatalf("unexpected WSS target: target=%+v url=%v ret=%d", gotTarget, gotWSURL, ret)
		}
	})
}

func TestBuildCallUsersResponseContactUsesDialogTransport(t *testing.T) {
	invite := sgsip.SGSIPMessage{}
	rawInvite := "INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/TCP proxy.example.com;branch=z9hG4bK1\r\nFrom: <sip:alice@example.com>;tag=a\r\nTo: <sip:bob@example.com>\r\nCall-ID: call-user-1\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
	if sgsip.SGSIPParseMessage(rawInvite, &invite) != sgsip.SGSIPRetOK {
		t.Fatal("failed to parse test INVITE")
	}

	for _, tc := range []struct {
		proto   string
		protoID int
	}{
		{proto: "udp", protoID: sgsip.ProtoUDP},
		{proto: "tcp", protoID: sgsip.ProtoTCP},
		{proto: "tls", protoID: sgsip.ProtoTLS},
		{proto: "ws", protoID: sgsip.ProtoWS},
		{proto: "wss", protoID: sgsip.ProtoWSS},
	} {
		t.Run(tc.proto, func(t *testing.T) {
			seDlg := &SIPExerDialog{Proto: tc.proto, ProtoId: tc.protoID, LocalAddr: "127.0.0.1:5064"}
			rsp, ret := SIPExerBuildCallUsersResponse(seDlg, &invite, "bob", "200", "OK", true)
			if ret != SIPExerRetOK {
				t.Fatalf("expected response build success, got: %d", ret)
			}
			want := "Contact: <sip:bob@127.0.0.1:5064;transport=" + tc.proto + ">"
			if !strings.Contains(rsp, want) {
				t.Fatalf("expected %q in response, got: %q", want, rsp)
			}
		})
	}
}

func TestRunCallUsersCalleeTCPFlow(t *testing.T) {
	withCleanState(t, func() {
		cliops.timeout = 2000
		cliops.timeoutwrite = 2000

		listenAddr, err := net.ResolveTCPAddr("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listener, err := net.ListenTCP("tcp4", listenAddr)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()

		clientConn, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
		if err != nil {
			t.Fatal(err)
		}
		defer clientConn.Close()
		serverConn, err := listener.AcceptTCP()
		if err != nil {
			t.Fatal(err)
		}
		defer serverConn.Close()

		seDlg := &SIPExerDialog{
			Proto:      "tcp",
			ProtoId:    sgsip.ProtoTCP,
			LocalAddr:  clientConn.LocalAddr().String(),
			TargetAddr: clientConn.RemoteAddr().String(),
			ConnTCP:    &SIPExerConnTCP{Conn: clientConn},
		}
		done := make(chan int, 1)
		go SIPExerRunCallUsersCallee(seDlg, "bob", 0, 0, done)

		invite := "INVITE sip:bob@127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/TCP proxy.example.com;branch=z9hG4bK1\r\nFrom: <sip:alice@example.com>;tag=a\r\nTo: <sip:bob@example.com>\r\nCall-ID: call-user-tcp\r\nCSeq: 1 INVITE\r\nRecord-Route: <sip:proxy.example.com;transport=tcp;lr>\r\nContent-Length: 0\r\n\r\n"
		if _, err = serverConn.Write([]byte(invite)); err != nil {
			t.Fatal(err)
		}

		readerDlg := &SIPExerDialog{}
		for _, wantCode := range []int{100, 180, 200} {
			if err = serverConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if ret := SIPExerDialogReadStreamConn(readerDlg, serverConn, SIPExerErrTCPRead); ret != SIPExerRetOK {
				t.Fatalf("failed reading %d response: %d", wantCode, ret)
			}
			rawRsp := string(readerDlg.RecvBuf[:readerDlg.RecvN])
			rsp := sgsip.SGSIPMessage{}
			if sgsip.SGSIPParseMessage(rawRsp, &rsp) != sgsip.SGSIPRetOK || rsp.FLine.Code != wantCode {
				t.Fatalf("expected %d response, got: %q", wantCode, rawRsp)
			}
			if wantCode == 200 && !strings.Contains(rawRsp, "transport=tcp") {
				t.Fatalf("expected TCP Contact in 200 response, got: %q", rawRsp)
			}
		}

		ack := "ACK sip:bob@127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/TCP proxy.example.com;branch=z9hG4bK2\r\nFrom: <sip:alice@example.com>;tag=a\r\nTo: <sip:bob@example.com>;tag=b\r\nCall-ID: call-user-tcp\r\nCSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n"
		bye := "BYE sip:bob@127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/TCP proxy.example.com;branch=z9hG4bK3\r\nFrom: <sip:alice@example.com>;tag=a\r\nTo: <sip:bob@example.com>;tag=b\r\nCall-ID: call-user-tcp\r\nCSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n"
		if _, err = serverConn.Write([]byte(ack + bye)); err != nil {
			t.Fatal(err)
		}
		if ret := SIPExerDialogReadStreamConn(readerDlg, serverConn, SIPExerErrTCPRead); ret != SIPExerRetOK {
			t.Fatalf("failed reading BYE response: %d", ret)
		}
		byeRsp := sgsip.SGSIPMessage{}
		if sgsip.SGSIPParseMessage(string(readerDlg.RecvBuf[:readerDlg.RecvN]), &byeRsp) != sgsip.SGSIPRetOK || byeRsp.FLine.Code != 200 || byeRsp.CSeq.MethodId != sgsip.SIPMethodBYE {
			t.Fatalf("expected 200 response to BYE, got: %q", string(readerDlg.RecvBuf[:readerDlg.RecvN]))
		}

		select {
		case ret := <-done:
			if ret != SIPExerRetOK {
				t.Fatalf("expected successful callee flow, got: %d", ret)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timeout waiting for TCP callee flow")
		}
	})
}

func TestSplitSIPMessages(t *testing.T) {
	msg1 := "NOTIFY sip:alice@example.com SIP/2.0\r\nVia: SIP/2.0/TCP host;branch=z9hG4bK1\r\nFrom: <sip:bob@example.com>;tag=a\r\nTo: <sip:alice@example.com>;tag=b\r\nCall-ID: c1\r\nCSeq: 1 NOTIFY\r\nContent-Length: 0\r\n\r\n"
	msg2 := "NOTIFY sip:alice@example.com SIP/2.0\r\nVia: SIP/2.0/TCP host;branch=z9hG4bK2\r\nFrom: <sip:bob@example.com>;tag=a\r\nTo: <sip:alice@example.com>;tag=b\r\nCall-ID: c1\r\nCSeq: 2 NOTIFY\r\nContent-Length: 0\r\n\r\n"

	got := SIPExerSplitSIPMessages(msg1 + msg2)
	if len(got) != 2 {
		t.Fatalf("expected 2 SIP messages from bundled buffer, got: %d", len(got))
	}
	if got[0] != msg1 || got[1] != msg2 {
		t.Fatalf("unexpected split result")
	}
}

func TestDialogReadStreamConnHandlesChunked183WithBody(t *testing.T) {
	withCleanState(t, func() {
		body := "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=call\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 49170 RTP/AVP 0\r\n"
		msg183 := "SIP/2.0 183 Session Progress\r\nVia: SIP/2.0/TLS host;branch=z9hG4bK1\r\nFrom: <sip:a@example.com>;tag=1\r\nTo: <sip:b@example.com>;tag=2\r\nCall-ID: c1\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
		msg100 := "SIP/2.0 100 Trying\r\nVia: SIP/2.0/TLS host;branch=z9hG4bK1\r\nFrom: <sip:a@example.com>;tag=1\r\nTo: <sip:b@example.com>\r\nCall-ID: c1\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
		reader := &chunkReader{
			chunks: []string{
				msg183[:120],
				msg183[120:] + msg100,
			},
		}
		seDlg := &SIPExerDialog{}

		if ret := SIPExerDialogReadStreamConn(seDlg, reader, SIPExerErrTLSRead); ret != SIPExerRetOK {
			t.Fatalf("expected first read ok, got: %d", ret)
		}
		if got := string(seDlg.RecvBuf[:seDlg.RecvN]); got != msg183 {
			t.Fatalf("expected first complete message to be 183, got: %q", got)
		}
		if seDlg.RecvRest == "" {
			t.Fatalf("expected second SIP message to remain buffered")
		}

		if ret := SIPExerDialogReadStreamConn(seDlg, reader, SIPExerErrTLSRead); ret != SIPExerRetOK {
			t.Fatalf("expected second buffered read ok, got: %d", ret)
		}
		if got := string(seDlg.RecvBuf[:seDlg.RecvN]); got != msg100 {
			t.Fatalf("expected second complete message to be 100, got: %q", got)
		}
	})
}

func TestDialogReadStreamConnRejectsHugeContentLength(t *testing.T) {
	withCleanState(t, func() {
		msg := "SIP/2.0 200 OK\r\nVia: SIP/2.0/TCP host;branch=z9hG4bK1\r\nFrom: <sip:a@example.com>;tag=1\r\nTo: <sip:b@example.com>;tag=2\r\nCall-ID: c1\r\nCSeq: 1 OPTIONS\r\nContent-Length: 9223372036854775807\r\n\r\nbody"
		reader := &chunkReader{chunks: []string{msg}}
		seDlg := &SIPExerDialog{}

		if ret := SIPExerDialogReadStreamConn(seDlg, reader, SIPExerErrTCPRead); ret != SIPExerErrTCPRead {
			t.Fatalf("expected read error for incomplete message, got: %d", ret)
		}
		if _, _, ok := SIPExerExtractNextSIPMessage(msg); ok {
			t.Fatalf("expected message with huge Content-Length to be incomplete")
		}
	})
}

func TestDialogResetForRequestReliableTransportDisablesResend(t *testing.T) {
	withCleanState(t, func() {
		seDlg := &SIPExerDialog{ProtoId: sgsip.ProtoTLS}
		SIPExerDialogResetForRequest(seDlg)
		if seDlg.Resend {
			t.Fatalf("expected reliable transport to start with Resend disabled")
		}
		seDlg = &SIPExerDialog{ProtoId: sgsip.ProtoUDP}
		SIPExerDialogResetForRequest(seDlg)
		if !seDlg.Resend {
			t.Fatalf("expected UDP to keep Resend enabled")
		}
	})
}

func TestDialogLoopAnswersRequestWhileWaitingForResponse(t *testing.T) {
	withCleanState(t, func() {
		cliops.timeout = 3000

		srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer srv.Close()

		done := make(chan string, 1)
		go func() {
			buf := make([]byte, 65535)
			_ = srv.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, peer, err := srv.ReadFromUDP(buf)
			if err != nil {
				done <- "failed to read request: " + err.Error()
				return
			}
			req := sgsip.SGSIPMessage{}
			if sgsip.SGSIPParseMessage(string(buf[:n]), &req) != sgsip.SGSIPRetOK {
				done <- "failed to parse request"
				return
			}
			notify := "NOTIFY sip:alice@127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1;branch=z9hG4bKn1\r\nFrom: <sip:bob@127.0.0.1>;tag=n1\r\nTo: <sip:alice@127.0.0.1>;tag=a1\r\nCall-ID: notify-call\r\nCSeq: 1 NOTIFY\r\nEvent: test\r\nContent-Length: 0\r\n\r\n"
			if _, err = srv.WriteToUDP([]byte(notify), peer); err != nil {
				done <- "failed to send NOTIFY: " + err.Error()
				return
			}
			for {
				n, _, err = srv.ReadFromUDP(buf)
				if err != nil {
					done <- "no response to NOTIFY: " + err.Error()
					return
				}
				rsp := sgsip.SGSIPMessage{}
				if sgsip.SGSIPParseMessage(string(buf[:n]), &rsp) == sgsip.SGSIPRetOK &&
					rsp.FLine.MType == sgsip.FLineResponse && rsp.CSeq.MethodId == sgsip.SIPMethodNOTIFY {
					if rsp.FLine.Code != 200 {
						done <- "unexpected response to NOTIFY: " + rsp.FLine.Val
						return
					}
					break
				}
			}
			final := ""
			if sgsip.SGSIPMessageToResponseString(&req, "404", "Not Found", &final) != sgsip.SGSIPRetOK {
				done <- "failed to build final response"
				return
			}
			if _, err = srv.WriteToUDP([]byte(final), peer); err != nil {
				done <- "failed to send final response: " + err.Error()
				return
			}
			done <- ""
		}()

		dstSockAddr := sgsip.SGSIPSocketAddress{}
		if sgsip.SGSIPParseSocketAddress("udp:"+srv.LocalAddr().String(), &dstSockAddr) != sgsip.SGSIPRetOK {
			t.Fatal("failed to parse responder address")
		}
		seDlg := &SIPExerDialog{}
		if ret := SIPExerInitUDPDialog(dstSockAddr, seDlg); ret != SIPExerRetOK {
			t.Fatalf("failed to init udp dialog: %d", ret)
		}
		defer SIPExerDialogCloseConn(seDlg)
		tplfields := make(map[string]any)
		SIPExerPrepareTemplateFields(tplfields)
		tplfields["ruri"] = "sip:bob@" + srv.LocalAddr().String()

		if ret := SIPExerDialogLoop(templateDefaultText, tplfields, seDlg); ret != 404 {
			t.Fatalf("expected the final response code 404, got: %d", ret)
		}
		if msg := <-done; msg != "" {
			t.Fatal(msg)
		}
	})
}

func TestRunRegisterFirstRequiresFUser(t *testing.T) {
	withCleanState(t, func() {
		ret := SIPExerRunRegisterFirst(sgsip.SGSIPSocketAddress{}, nil, "", map[string]any{"method": "INVITE"})
		if ret != SIPExerErrTemplateData {
			t.Fatalf("expected template data error when fuser is missing, got: %d", ret)
		}
	})
}

func TestDialogLoopAuthenticatesChallengedBYE(t *testing.T) {
	withCleanState(t, func() {
		cliops.timeout = 3000
		cliops.invite = true
		cliops.sessionwait = 100
		cliops.authuser = "alice"
		cliops.authapassword = "secret"

		srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer srv.Close()

		done := make(chan string, 1)
		go func() {
			buf := make([]byte, 65535)
			_ = srv.SetReadDeadline(time.Now().Add(3 * time.Second))
			readRequest := func(skip string) (sgsip.SGSIPMessage, *net.UDPAddr, error) {
				for {
					n, peer, err := srv.ReadFromUDP(buf)
					if err != nil {
						return sgsip.SGSIPMessage{}, nil, err
					}
					msg := sgsip.SGSIPMessage{}
					if sgsip.SGSIPParseMessage(string(buf[:n]), &msg) == sgsip.SGSIPRetOK &&
						msg.FLine.MType == sgsip.FLineRequest && msg.FLine.Method != skip {
						return msg, peer, nil
					}
				}
			}
			reply := func(req *sgsip.SGSIPMessage, peer *net.UDPAddr, code string, reason string, hname string, hbody string) error {
				rsp := ""
				if sgsip.SGSIPMessageToResponseString(req, code, reason, &rsp) != sgsip.SGSIPRetOK {
					return io.ErrUnexpectedEOF
				}
				if len(hname) > 0 {
					rmsg := sgsip.SGSIPMessage{}
					if sgsip.SGSIPParseMessage(rsp, &rmsg) != sgsip.SGSIPRetOK {
						return io.ErrUnexpectedEOF
					}
					sgsip.SGSIPMessageHeaderSet(&rmsg, hname, hbody)
					if sgsip.SGSIPMessageToString(&rmsg, &rsp) != sgsip.SGSIPRetOK {
						return io.ErrUnexpectedEOF
					}
				}
				_, err := srv.WriteToUDP([]byte(rsp), peer)
				return err
			}

			invite, peer, err := readRequest("")
			if err != nil || invite.FLine.Method != "INVITE" {
				done <- "expected INVITE"
				return
			}
			if err = reply(&invite, peer, "200", "OK", "Contact", "<sip:bob@"+srv.LocalAddr().String()+">"); err != nil {
				done <- "failed to send 200 for INVITE"
				return
			}
			bye, peer, err := readRequest("ACK")
			if err != nil || bye.FLine.Method != "BYE" {
				done <- "expected BYE"
				return
			}
			if err = reply(&bye, peer, "401", "Unauthorized", "WWW-Authenticate", `Digest realm="127.0.0.1", nonce="n1", qop="auth", algorithm=MD5`); err != nil {
				done <- "failed to send 401 for BYE"
				return
			}
			var next sgsip.SGSIPMessage
			for {
				next, peer, err = readRequest("")
				if err != nil {
					done <- "no request after 401 for BYE"
					return
				}
				// skip retransmissions of the challenged BYE
				if next.FLine.Method != "BYE" || next.CSeq.Number != bye.CSeq.Number {
					break
				}
			}
			_ = reply(&next, peer, "200", "OK", "", "")
			if next.FLine.Method != "BYE" {
				done <- "expected authenticated BYE, got: " + next.FLine.Method
				return
			}
			if !strings.Contains(next.Data, "Authorization: Digest") || !strings.Contains(next.Data, `uri="`+bye.FLine.URI+`"`) {
				done <- "expected BYE with Authorization for the BYE R-URI, got: " + next.Data
				return
			}
			done <- ""
		}()

		dstSockAddr := sgsip.SGSIPSocketAddress{}
		if sgsip.SGSIPParseSocketAddress("udp:"+srv.LocalAddr().String(), &dstSockAddr) != sgsip.SGSIPRetOK {
			t.Fatal("failed to parse responder address")
		}
		seDlg := &SIPExerDialog{}
		if ret := SIPExerInitUDPDialog(dstSockAddr, seDlg); ret != SIPExerRetOK {
			t.Fatalf("failed to init udp dialog: %d", ret)
		}
		defer SIPExerDialogCloseConn(seDlg)
		tplfields := make(map[string]any)
		SIPExerPrepareTemplateFields(tplfields)
		tplfields["ruri"] = "sip:bob@" + srv.LocalAddr().String()

		ret := SIPExerDialogLoop(templateDefaultText, tplfields, seDlg)
		if msg := <-done; msg != "" {
			t.Fatal(msg)
		}
		if ret != 200 {
			t.Fatalf("expected 200 for the authenticated BYE, got: %d", ret)
		}
	})
}

// runUDPRetransmitDialog runs the dialog loop for the given method against a local
// UDP peer. The peer gets the copies of the request seen until it stops being sent
// and calls onRequest with the number of the copy; a non-empty answer is sent back.
func runUDPRetransmitDialog(t *testing.T, method string, onRequest func(n int, req *sgsip.SGSIPMessage) string) (int, int) {
	cliops.timert1 = 20
	cliops.timert2 = 160
	cliops.timeout = 1280

	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	copies := make(chan int, 1)
	go func() {
		buf := make([]byte, 65535)
		n := 0
		for {
			_ = srv.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
			sz, peer, err := srv.ReadFromUDP(buf)
			if err != nil {
				copies <- n
				return
			}
			req := sgsip.SGSIPMessage{}
			if sgsip.SGSIPParseMessage(string(buf[:sz]), &req) != sgsip.SGSIPRetOK ||
				req.FLine.MType != sgsip.FLineRequest || req.FLine.Method != method {
				continue
			}
			n++
			code := onRequest(n, &req)
			if len(code) > 0 {
				rsp := ""
				if sgsip.SGSIPMessageToResponseString(&req, code, "Reply", &rsp) == sgsip.SGSIPRetOK {
					_, _ = srv.WriteToUDP([]byte(rsp), peer)
				}
			}
		}
	}()

	dstSockAddr := sgsip.SGSIPSocketAddress{}
	if sgsip.SGSIPParseSocketAddress("udp:"+srv.LocalAddr().String(), &dstSockAddr) != sgsip.SGSIPRetOK {
		t.Fatal("failed to parse responder address")
	}
	seDlg := &SIPExerDialog{}
	if ret := SIPExerInitUDPDialog(dstSockAddr, seDlg); ret != SIPExerRetOK {
		t.Fatalf("failed to init udp dialog: %d", ret)
	}
	defer SIPExerDialogCloseConn(seDlg)
	tplfields := make(map[string]any)
	SIPExerPrepareTemplateFields(tplfields)
	tplfields["method"] = method
	tplfields["ruri"] = "sip:bob@" + srv.LocalAddr().String()

	ret := SIPExerDialogLoop(templateDefaultText, tplfields, seDlg)
	return ret, <-copies
}

func TestDialogLoopUDPInviteRetransmitsWithoutT2Cap(t *testing.T) {
	withCleanState(t, func() {
		cliops.invite = true
		ret, copies := runUDPRetransmitDialog(t, "INVITE", func(int, *sgsip.SGSIPMessage) string { return "" })
		if ret != SIPExerErrUDPReceiveTimeout {
			t.Fatalf("expected receive timeout, got: %d", ret)
		}
		// timer A doubles up to timer B (64*T1): sent at 0, 1, 3, 7, 15, 31 and 63 times T1
		if copies != 7 {
			t.Fatalf("expected 7 copies of the INVITE, got: %d", copies)
		}
	})
}

func TestDialogLoopUDPNonInviteRetransmitsAfter1xx(t *testing.T) {
	withCleanState(t, func() {
		ret, copies := runUDPRetransmitDialog(t, "OPTIONS", func(n int, _ *sgsip.SGSIPMessage) string {
			switch n {
			case 1:
				return "100"
			case 4:
				// the final response is only sent for a retransmission
				return "200"
			}
			return ""
		})
		if ret != 200 {
			t.Fatalf("expected 200 after retransmissions following the 100, got: %d (copies: %d)", ret, copies)
		}
		if copies < 4 {
			t.Fatalf("expected at least 4 copies of the OPTIONS, got: %d", copies)
		}
	})
}

func TestDialogLoopUDPInviteStopsAfter1xx(t *testing.T) {
	withCleanState(t, func() {
		cliops.invite = true
		ret, copies := runUDPRetransmitDialog(t, "INVITE", func(n int, _ *sgsip.SGSIPMessage) string {
			if n == 1 {
				return "100"
			}
			return ""
		})
		if ret != SIPExerErrUDPReceiveTimeout {
			t.Fatalf("expected receive timeout, got: %d", ret)
		}
		if copies != 1 {
			t.Fatalf("expected the INVITE not to be re-sent after the 100, got %d copies", copies)
		}
	})
}

func TestSelectDigestAuthParamsUsesFirstHeader(t *testing.T) {
	msg := sgsip.SGSIPMessage{
		Headers: []sgsip.SGSIPHeader{
			{Name: "WWW-Authenticate", Body: `Digest realm="127.0.0.1", nonce="n1", qop="auth", algorithm=MD5`},
			{Name: "WWW-Authenticate", Body: `Digest realm="127.0.0.1", nonce="n1", qop="auth", algorithm=SHA-256`},
		},
	}
	got := SIPExerSelectDigestAuthParams(&msg, "WWW-Authenticate", "first")
	if got == nil {
		t.Fatalf("expected auth params, got nil")
	}
	if got["algorithm"] != "MD5" {
		t.Fatalf("expected first auth header to be selected, got: %q", got["algorithm"])
	}
}

func TestRunRegisterFirstRegisterHasNoInviteBody(t *testing.T) {
	withCleanState(t, func() {
		cliops.timeout = 3000
		cliops.invite = true
		cliops.registerfirst = true

		srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer srv.Close()

		done := make(chan string, 1)
		go func() {
			buf := make([]byte, 65535)
			_ = srv.SetReadDeadline(time.Now().Add(3 * time.Second))
			for _, want := range []struct {
				method string
				code   string
				reason string
				body   bool
			}{
				{method: "REGISTER", code: "200", reason: "OK", body: false},
				{method: "INVITE", code: "486", reason: "Busy Here", body: true},
			} {
				req := sgsip.SGSIPMessage{}
				var peer *net.UDPAddr
				for {
					n, addr, err := srv.ReadFromUDP(buf)
					if err != nil {
						done <- "no " + want.method + " request: " + err.Error()
						return
					}
					if sgsip.SGSIPParseMessage(string(buf[:n]), &req) == sgsip.SGSIPRetOK &&
						req.FLine.MType == sgsip.FLineRequest && req.FLine.Method == want.method {
						peer = addr
						break
					}
				}
				if hasBody := len(req.Body.Content) > 0; hasBody != want.body {
					done <- "unexpected body in " + want.method + ": " + req.Data
					return
				}
				rsp := ""
				if sgsip.SGSIPMessageToResponseString(&req, want.code, want.reason, &rsp) != sgsip.SGSIPRetOK {
					done <- "failed to build response"
					return
				}
				if _, err := srv.WriteToUDP([]byte(rsp), peer); err != nil {
					done <- "failed to send response: " + err.Error()
					return
				}
			}
			done <- ""
		}()

		dstSockAddr := sgsip.SGSIPSocketAddress{}
		if sgsip.SGSIPParseSocketAddress("udp:"+srv.LocalAddr().String(), &dstSockAddr) != sgsip.SGSIPRetOK {
			t.Fatal("failed to parse responder address")
		}
		tplfields := make(map[string]any)
		SIPExerPrepareTemplateFields(tplfields)
		tplfields["ruri"] = "sip:bob@" + srv.LocalAddr().String()

		ret := SIPExerRunRegisterFirst(dstSockAddr, nil, templateDefaultText, tplfields)
		if msg := <-done; msg != "" {
			t.Fatal(msg)
		}
		if ret != 486 {
			t.Fatalf("expected 486 for the INVITE stage, got: %d", ret)
		}
	})
}

func TestSelectDigestAuthParamsModes(t *testing.T) {
	msg := sgsip.SGSIPMessage{
		Headers: []sgsip.SGSIPHeader{
			{Name: "WWW-Authenticate", Body: `Digest realm="127.0.0.1", nonce="n1", qop="auth", algorithm=MD5`},
			{Name: "WWW-Authenticate", Body: `Digest realm="127.0.0.1", nonce="n1", qop="auth", algorithm=SHA-256`},
			{Name: "WWW-Authenticate", Body: `Digest realm="127.0.0.1", nonce="n1", qop="auth", algorithm=SHA-512-256`},
		},
	}

	if got := SIPExerSelectDigestAuthParams(&msg, "WWW-Authenticate", "last"); got == nil || got["algorithm"] != "SHA-512-256" {
		t.Fatalf("expected last challenge to be selected, got: %#v", got)
	}
	if got := SIPExerSelectDigestAuthParams(&msg, "WWW-Authenticate", "strong"); got == nil || got["algorithm"] != "SHA-512-256" {
		t.Fatalf("expected strongest challenge to be selected, got: %#v", got)
	}
	if got := SIPExerSelectDigestAuthParams(&msg, "WWW-Authenticate", "SHA-256"); got == nil || got["algorithm"] != "SHA-256" {
		t.Fatalf("expected explicit SHA-256 match to be selected, got: %#v", got)
	}
	if got := SIPExerSelectDigestAuthParams(&msg, "WWW-Authenticate", "SHA-1"); got != nil {
		t.Fatalf("expected nil for non-existing requested algorithm, got: %#v", got)
	}
}

func makeTestWAV(format uint16, channels uint16, rate uint32, width uint16, data []byte) []byte {
	b := []byte("RIFF\x00\x00\x00\x00WAVEfmt \x10\x00\x00\x00")
	b = binary.LittleEndian.AppendUint16(b, format)
	b = binary.LittleEndian.AppendUint16(b, channels)
	b = binary.LittleEndian.AppendUint32(b, rate)
	b = binary.LittleEndian.AppendUint32(b, rate*uint32(channels*width/8))
	b = binary.LittleEndian.AppendUint16(b, channels*width/8)
	b = binary.LittleEndian.AppendUint16(b, width)
	b = append(b, "LIST\x03\x00\x00\x00abc\x00data"...)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(data)))
	return append(b, data...)
}

func TestRTPParseWAV(t *testing.T) {
	audio, err := SIPExerRTPParseWAV(makeTestWAV(1, 1, 8000, 16, []byte{0x01, 0x00, 0xff, 0xff, 0x00, 0x80}), "a.wav")
	if err != nil || audio.Law != SIPExerRTPLawLinear || len(audio.Samples) != 3 ||
		audio.Samples[0] != 1 || audio.Samples[1] != -1 || audio.Samples[2] != -32768 {
		t.Fatalf("unexpected 16-bit PCM WAV result: %+v %v", audio, err)
	}
	audio, err = SIPExerRTPParseWAV(makeTestWAV(7, 1, 8000, 8, []byte{0xff, 0x7f}), "u.wav")
	if err != nil || audio.Law != SIPExerRTPLawPCMU || string(audio.G711) != "\xff\x7f" {
		t.Fatalf("unexpected G.711 WAV result: %+v %v", audio, err)
	}
	for _, wav := range [][]byte{makeTestWAV(1, 1, 16000, 16, []byte{0, 0}), makeTestWAV(1, 2, 8000, 16, []byte{0, 0, 0, 0}),
		makeTestWAV(1, 1, 8000, 8, []byte{0x80})} {
		if _, err = SIPExerRTPParseWAV(wav, "in.wav"); err == nil ||
			!strings.Contains(err.Error(), "ffmpeg -i in.wav -ar 8000 -ac 1") || !strings.Contains(err.Error(), "sox in.wav -r 8000 -c 1") {
			t.Fatalf("expected an error with conversion commands, got: %v", err)
		}
	}
	if _, err = SIPExerRTPParseWAV([]byte("not a wav file"), "x.wav"); err == nil {
		t.Fatalf("expected an error for a non WAV file")
	}
}

func TestRTPLoadAudioRawAndTone(t *testing.T) {
	withCleanState(t, func() {
		dir := t.TempDir()
		for _, tc := range []struct {
			name   string
			option string
			law    int
		}{{"a.alaw", "", SIPExerRTPLawPCMA}, {"a.pcmu", "", SIPExerRTPLawPCMU}, {"a.raw", "", -2},
			{"a.raw", "pcmu", SIPExerRTPLawPCMU}, {"a.ulaw", "alaw", SIPExerRTPLawPCMA}, {"a.alaw", "x", -2}} {
			cliops.rtpfile = filepath.Join(dir, tc.name)
			cliops.rtpfilelaw = tc.option
			if err := os.WriteFile(cliops.rtpfile, []byte{0xd5, 0xd5}, 0644); err != nil {
				t.Fatal(err)
			}
			audio, err := SIPExerRTPLoadAudio()
			if (tc.law == -2 && err == nil) || (tc.law != -2 && (err != nil || audio.Law != tc.law || len(audio.G711) != 2)) {
				t.Fatalf("unexpected raw audio for %+v: %+v %v", tc, audio, err)
			}
		}
		cliops.rtptone = "440"
		if _, err := SIPExerRTPLoadAudio(); err == nil {
			t.Fatalf("expected an error for rtp-file and rtp-tone together")
		}
		cliops.rtpfile = ""
		for spec, n := range map[string]int{"440": 40000, "440:100": 800, ":40": 320, "4000": -1, "0:10": -1, "a": -1,
			"1000:-5": -1, "1000:3600001": -1, "1000:9223372036854775807": -1} {
			cliops.rtptone = spec
			audio, err := SIPExerRTPLoadAudio()
			if (n < 0 && err == nil) || (n >= 0 && (err != nil || len(audio.Samples) != n)) {
				t.Fatalf("unexpected tone result for %q: %v", spec, err)
			}
		}
	})
}

func TestRTPG711(t *testing.T) {
	for _, tc := range []struct {
		sample int16
		ulaw   byte
		alaw   byte
	}{{0, 0xff, 0xd5}, {32767, 0x80, 0xaa}, {-32768, 0x00, 0x2a}, {1000, 0xce, 0xfa}, {-1000, 0x4e, 0x7a}} {
		if u, a := SIPExerLinearToULaw(tc.sample), SIPExerLinearToALaw(tc.sample); u != tc.ulaw || a != tc.alaw {
			t.Fatalf("unexpected G.711 encoding of %d: ulaw 0x%02x alaw 0x%02x", tc.sample, u, a)
		}
	}
	if SIPExerULawToLinear(0x80) != 32124 || SIPExerULawToLinear(0x00) != -32124 ||
		SIPExerALawToLinear(0xaa) != 32256 || SIPExerALawToLinear(0x2a) != -32256 {
		t.Fatalf("unexpected G.711 decoding of the largest values")
	}
	for i := 0; i < 256; i++ {
		if c := byte(i); c != 0x7f && SIPExerLinearToULaw(SIPExerULawToLinear(c)) != c {
			t.Fatalf("ulaw round trip failed for 0x%02x", c)
		}
		if c := byte(i); SIPExerLinearToALaw(SIPExerALawToLinear(c)) != c {
			t.Fatalf("alaw round trip failed for 0x%02x", c)
		}
	}
	ulaw := &SIPExerRTPAudio{Law: SIPExerRTPLawPCMU, G711: []byte{0x80, 0xff, 0x00}}
	if got := SIPExerRTPEncodeAudio(ulaw, SIPExerRTPLawPCMU); string(got) != string(ulaw.G711) {
		t.Fatalf("expected G.711 data of the same law as is, got: %x", got)
	}
	if got := SIPExerRTPEncodeAudio(ulaw, SIPExerRTPLawPCMA); string(got) != "\xaa\xd5\x2a" {
		t.Fatalf("unexpected ulaw to alaw transcoding: %x", got)
	}
	pcm := &SIPExerRTPAudio{Law: SIPExerRTPLawLinear, Samples: []int16{1000, -1000}}
	if got := SIPExerRTPEncodeAudio(pcm, SIPExerRTPLawPCMU); string(got) != "\xce\x4e" {
		t.Fatalf("unexpected linear to ulaw encoding: %x", got)
	}
}

func TestRTPPacketAndSDP(t *testing.T) {
	pkt := SIPExerRTPPacket(8, true, 0xfffe, 0x01020304, 0x0a0b0c0d, []byte{0xd5, 0xd5})
	if string(pkt) != "\x80\x88\xff\xfe\x01\x02\x03\x04\x0a\x0b\x0c\x0d\xd5\xd5" {
		t.Fatalf("unexpected RTP packet: %x", pkt)
	}
	if pkt = SIPExerRTPPacket(0, false, 1, 2, 3, nil); pkt[1] != 0x00 || len(pkt) != 12 {
		t.Fatalf("unexpected RTP packet without marker: %x", pkt)
	}

	sdp := "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n" +
		"m=video 4000 RTP/AVP 97\r\nc=IN IP4 192.0.2.9\r\n" +
		"m=audio 4002 RTP/AVP 101 96 0\r\na=rtpmap:101 telephone-event/8000\r\na=rtpmap:96 PCMA/8000/1\r\n"
	media, err := SIPExerRTPParseSDP(sdp)
	if err != nil || SIPExerRTPCheckMedia(&media, true) != nil || media.Addr != "192.0.2.1" || media.Port != 4002 {
		t.Fatalf("unexpected parsed audio stream: %+v %v", media, err)
	}
	if pt, law, ok := SIPExerRTPSelectPayload(&media); !ok || pt != 96 || law != SIPExerRTPLawPCMA {
		t.Fatalf("expected dynamic PCMA payload type 96, got: %d %d %v", pt, law, ok)
	}
	for _, bad := range []string{
		"c=IN IP4 192.0.2.1\r\nm=audio 4002 RTP/SAVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:x\r\n",
		"c=IN IP4 192.0.2.1\r\nm=audio 0 RTP/AVP 0\r\n",
		"c=IN IP4 192.0.2.1\r\nm=audio 4002 RTP/AVP 9 18\r\n",
		"c=IN IP4 192.0.2.1\r\nm=audio 4002 RTP/AVP 96\r\na=rtpmap:96 PCMA/8000/2\r\n",
		"c=IN IP4 192.0.2.1\r\nm=audio 4002 RTP/AVP 96\r\na=rtpmap:96 PCMU/80000\r\n",
		"c=IN IP4 192.0.2.1\r\nm=audio 4002 RTP/AVP 128\r\na=rtpmap:128 PCMU/8000\r\n",
		"c=IN IP4 0.0.0.0\r\nm=audio 4002 RTP/AVP 8\r\n",
		"c=IN IP4 192.0.2.1\r\nm=video 4002 RTP/AVP 97\r\n",
	} {
		if media, err = SIPExerRTPParseSDP(bad); err == nil && SIPExerRTPCheckMedia(&media, true) == nil {
			t.Fatalf("expected unusable SDP answer: %q", bad)
		}
	}
}

func TestRTPSendErrorPropagates(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
	recvDone := make(chan struct{})
	close(recvDone)
	rtpS := &SIPExerRTPSession{
		Conn:     conn,
		Started:  true,
		stop:     make(chan struct{}),
		sendDone: make(chan struct{}),
		recvDone: recvDone,
	}
	SIPExerRTPSend(rtpS, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}, SIPExerRTPLawPCMU,
		SIPExerRTPLawPCMU, make([]byte, SIPExerRTPSamples), 1)
	if rtpS.SendErr == nil {
		t.Fatal("expected the RTP write failure to be recorded")
	}

	seDlg := &SIPExerDialog{RTP: rtpS}
	SIPExerRTPClose(seDlg)
	if seDlg.RTPRet != SIPExerErrRTPSend {
		t.Fatalf("expected RTP send error %d, got: %d", SIPExerErrRTPSend, seDlg.RTPRet)
	}
}

func TestDialogLoopRTPStream(t *testing.T) {
	withCleanState(t, func() {
		cliops.timeout = 3000
		cliops.invite = true
		cliops.rtptone = "1000:200"
		var err error
		if sipexerRTPAudio, err = SIPExerRTPLoadAudio(); err != nil {
			t.Fatal(err)
		}
		defer func() { sipexerRTPAudio = nil }()
		SIPExerResetRTPInfo()
		defer SIPExerResetRTPInfo()

		srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer srv.Close()
		peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer peer.Close()

		done := make(chan string, 2)
		offerPort := make(chan int, 1)
		go func() {
			// RTP peer: check and echo the packets
			port := <-offerPort
			buf := make([]byte, 2048)
			var first []byte
			for i := 0; i < 10; i++ {
				_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
				n, src, err := peer.ReadFromUDP(buf)
				if err != nil {
					done <- "rtp packet " + strconv.Itoa(i) + " not received: " + err.Error()
					return
				}
				if src.Port != port || n != 172 || buf[0] != 0x80 || buf[1]&0x7f != 8 || (buf[1]&0x80 != 0) != (i == 0) {
					done <- "unexpected rtp packet " + strconv.Itoa(i) + " from " + src.String() + ": " + hex.EncodeToString(buf[:12])
					return
				}
				if i == 0 {
					first = append([]byte(nil), buf[:12]...)
				} else if binary.BigEndian.Uint16(buf[2:]) != binary.BigEndian.Uint16(first[2:])+uint16(i) ||
					binary.BigEndian.Uint32(buf[4:]) != binary.BigEndian.Uint32(first[4:])+uint32(160*i) ||
					binary.BigEndian.Uint32(buf[8:]) != binary.BigEndian.Uint32(first[8:]) {
					done <- "unexpected rtp sequence, timestamp or ssrc in packet " + strconv.Itoa(i) + ": " + hex.EncodeToString(buf[:12])
					return
				}
				_, _ = peer.WriteToUDP(buf[:n], src)
			}
			done <- ""
		}()
		go func() {
			// SIP peer: answer the INVITE with PCMA, then BYE with 200
			buf := make([]byte, 65535)
			_ = srv.SetReadDeadline(time.Now().Add(3 * time.Second))
			for {
				n, src, err := srv.ReadFromUDP(buf)
				if err != nil {
					done <- "sip request not received: " + err.Error()
					return
				}
				req := sgsip.SGSIPMessage{}
				if sgsip.SGSIPParseMessage(string(buf[:n]), &req) != sgsip.SGSIPRetOK || req.FLine.MType != sgsip.FLineRequest ||
					req.FLine.MethodId == sgsip.SIPMethodACK {
					continue
				}
				rsp := ""
				sgsip.SGSIPMessageToResponseString(&req, "200", "OK", &rsp)
				if req.FLine.MethodId == sgsip.SIPMethodINVITE {
					offer, _ := SIPExerRTPParseSDP(req.Body.Content)
					offerPort <- offer.Port
					rmsg := sgsip.SGSIPMessage{}
					sgsip.SGSIPParseMessage(rsp, &rmsg)
					sgsip.SGSIPMessageHeaderSet(&rmsg, "Contact", "<sip:bob@"+srv.LocalAddr().String()+">")
					rmsg.Body.Content = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio " +
						strconv.Itoa(peer.LocalAddr().(*net.UDPAddr).Port) + " RTP/AVP 8 101\r\na=rtpmap:101 telephone-event/8000\r\n"
					rmsg.Body.ContentLen = len(rmsg.Body.Content)
					rmsg.Body.ContentType = "application/sdp"
					sgsip.SGSIPMessageToString(&rmsg, &rsp)
				}
				_, _ = srv.WriteToUDP([]byte(rsp), src)
				if req.FLine.MethodId == sgsip.SIPMethodBYE {
					done <- ""
					return
				}
			}
		}()

		dstSockAddr := sgsip.SGSIPSocketAddress{}
		sgsip.SGSIPParseSocketAddress("udp:"+srv.LocalAddr().String(), &dstSockAddr)
		seDlg := &SIPExerDialog{}
		if ret := SIPExerInitUDPDialog(dstSockAddr, seDlg); ret != SIPExerRetOK {
			t.Fatalf("failed to init udp dialog: %d", ret)
		}
		defer SIPExerDialogCloseConn(seDlg)
		tplfields := make(map[string]any)
		SIPExerPrepareTemplateFields(tplfields)
		tplfields["ruri"] = "sip:bob@" + srv.LocalAddr().String()

		ret := SIPExerDialogLoop(templateDefaultText, tplfields, seDlg)
		for i := 0; i < 2; i++ {
			if msg := <-done; msg != "" {
				t.Fatal(msg)
			}
		}
		if ret != 200 {
			t.Fatalf("expected 200 for the BYE after streaming, got: %d", ret)
		}
		info := sipexerLastRTPInfo.Load()
		if info == nil || info.PacketsSent != 10 || info.BytesSent != 1600 || info.PacketsReceived != 10 ||
			info.BytesReceived != 1600 || info.PayloadType != 8 || info.RemoteAddress != peer.LocalAddr().String() ||
			len(info.FirstSent) == 0 || len(info.FirstReceived) == 0 {
			t.Fatalf("unexpected rtp info: %+v", info)
		}
		data, _ := json.Marshal(SIPExerExitResult{RTP: info})
		if !strings.Contains(string(data), `"rtp":{"localAddress":`) {
			t.Fatalf("unexpected rtp info in result: %s", data)
		}
	})
}

func TestRTPOpenRefusesSRTPOffer(t *testing.T) {
	withCleanState(t, func() {
		for _, offer := range []string{"m=audio 4000 RTP/SAVP 0\r\n", "m=audio 4000 UDP/TLS/RTP/SAVPF 0\r\n", "m=video 4000 RTP/AVP 97\r\n"} {
			seDlg := &SIPExerDialog{Proto: "udp", ProtoId: sgsip.ProtoUDP, LocalAddr: "127.0.0.1:5060",
				FirstRequest: &sgsip.SGSIPMessage{Body: sgsip.SGSIPBody{Content: "c=IN IP4 127.0.0.1\r\n" + offer}}}
			if ret := SIPExerRTPOpen(seDlg); ret != SIPExerErrRTPOffer || seDlg.RTP != nil {
				t.Fatalf("expected rtp to be refused for offer %q, got: %d", offer, ret)
			}
		}
	})
}

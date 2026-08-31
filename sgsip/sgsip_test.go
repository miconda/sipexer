package sgsip

import (
	"regexp"
	"strings"
	"testing"
)

func mustParseMessage(t *testing.T, raw string) SGSIPMessage {
	t.Helper()
	msg := SGSIPMessage{}
	if ret := SGSIPParseMessage(raw, &msg); ret != SGSIPRetOK {
		t.Fatalf("SGSIPParseMessage failed: ret=%d", ret)
	}
	return msg
}

func TestSGAddrTypeHelpers(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int
	}{
		{name: "ipv4", in: "127.0.0.1", want: AFIPv4},
		{name: "ipv6", in: "::1", want: AFIPv6},
		{name: "host", in: "example.com", want: AFHost},
		{name: "ipv6-brackets", in: "[::1]", want: AFIPv6},
		{name: "invalid-brackets", in: "[::1", want: AFNONE},
		{name: "empty", in: "", want: AFNONE},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := SGAddrType(tc.in)
			if strings.Contains(tc.name, "brackets") {
				got = SGAddrTypeEx(tc.in)
			}
			if got != tc.want {
				t.Fatalf("unexpected addr type: got=%d want=%d", got, tc.want)
			}
		})
	}
}

func TestSetters(t *testing.T) {
	var p string
	var pid int
	if SGSIPSetProto("tls", &p, &pid) != SGSIPRetOK || p != "tls" || pid != ProtoTLS {
		t.Fatalf("unexpected proto set: %q %d", p, pid)
	}
	if SGSIPSetProto("bad", &p, &pid) != SGSIPRetErr {
		t.Fatalf("expected invalid proto error")
	}

	var s string
	var sid int
	if SGSIPSetSchema("SIPS", &s, &sid) != SGSIPRetOK || s != "sips" || sid != SchemaSIPS {
		t.Fatalf("unexpected schema set: %q %d", s, sid)
	}
	if SGSIPSetSchema("bad", &s, &sid) != SGSIPRetErr {
		t.Fatalf("expected invalid schema error")
	}

	var mid int
	SGSIPSetMethodId("invite", &mid)
	if mid != SIPMethodINVITE {
		t.Fatalf("unexpected method id for invite: %d", mid)
	}
	SGSIPSetMethodId("x-custom", &mid)
	if mid != SIPMethodOTHER {
		t.Fatalf("unexpected method id for custom method: %d", mid)
	}
}

func TestParseSocketAddress(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantRet int
		proto   string
		addr    string
		port    string
	}{
		{name: "host-only", in: "example.com", wantRet: SGSIPRetOK, proto: "udp", addr: "example.com", port: "5060"},
		{name: "host-port", in: "example.com:5070", wantRet: SGSIPRetOK, proto: "udp", addr: "example.com", port: "5070"},
		{name: "proto-host-port", in: "tcp:127.0.0.1:5080", wantRet: SGSIPRetOK, proto: "tcp", addr: "127.0.0.1", port: "5080"},
		{name: "ipv6", in: "tls:[::1]:5061", wantRet: SGSIPRetOK, proto: "tls", addr: "[::1]", port: "5061"},
		{name: "ipv6-default-port", in: "tcp:[::1]", wantRet: SGSIPRetOK, proto: "tcp", addr: "[::1]", port: "5060"},
		{name: "invalid-port", in: "udp:127.0.0.1:abc", wantRet: SGSIPRetErrSocketAddressPortVal},
		{name: "empty", in: "", wantRet: SGSIPRetErr},
		{name: "protocol-only", in: "tcp:", wantRet: SGSIPRetErrSocketAddressPort},
		{name: "empty-host", in: ":5060", wantRet: SGSIPRetErrSocketAddressPort},
		{name: "unterminated-ipv6", in: "tcp:[::1", wantRet: SGSIPRetErrSocketAddressAFIPv6},
		{name: "ipv6-empty-port", in: "tcp:[::1]:", wantRet: SGSIPRetErrSocketAddressPort},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var sa SGSIPSocketAddress
			ret := SGSIPParseSocketAddress(tc.in, &sa)
			if ret != tc.wantRet {
				t.Fatalf("unexpected return: got=%d want=%d", ret, tc.wantRet)
			}
			if ret == SGSIPRetOK {
				if sa.Proto != tc.proto || sa.Addr != tc.addr || sa.Port != tc.port {
					t.Fatalf("unexpected parsed socket addr: %+v", sa)
				}
			}
		})
	}
}

func TestParseURI(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantRet int
		addr    string
		port    string
		proto   string
	}{
		{name: "simple", in: "sip:example.com", wantRet: SGSIPRetOK, addr: "example.com", port: "5060", proto: "udp"},
		{name: "sips-simple", in: "sips:example.com", wantRet: SGSIPRetOK, addr: "example.com", port: "5061", proto: "tls"},
		{name: "sips-user", in: "sips:alice@example.com", wantRet: SGSIPRetOK, addr: "example.com", port: "5061", proto: "tls"},
		{name: "sips-ipv6", in: "sips:[::1]", wantRet: SGSIPRetOK, addr: "[::1]", port: "5061", proto: "tls"},
		{name: "sips-explicit-port", in: "sips:example.com:5071", wantRet: SGSIPRetOK, addr: "example.com", port: "5071", proto: "tls"},
		{name: "sips-tcp", in: "sips:example.com;transport=tcp", wantRet: SGSIPRetOK, addr: "example.com", port: "5061", proto: "tls"},
		{name: "sips-tls", in: "sips:example.com;transport=tls", wantRet: SGSIPRetOK, addr: "example.com", port: "5061", proto: "tls"},
		{name: "sips-wss", in: "sips:example.com;transport=wss", wantRet: SGSIPRetOK, addr: "example.com", port: "5061", proto: "wss"},
		{name: "sips-udp-rejected", in: "sips:example.com;transport=udp", wantRet: SGSIPRetErrURIProto},
		{name: "sips-ws-rejected", in: "sips:example.com;transport=ws", wantRet: SGSIPRetErrURIProto},
		{name: "with-user-and-port", in: "sip:alice@example.com:5070", wantRet: SGSIPRetOK, addr: "example.com", port: "5070", proto: "udp"},
		{name: "with-transport", in: "sip:example.com:5061;transport=tls", wantRet: SGSIPRetOK, addr: "example.com", port: "5061", proto: "tls"},
		{name: "ipv6", in: "sip:[::1]:5060;transport=udp", wantRet: SGSIPRetOK, addr: "[::1]", port: "5060", proto: "udp"},
		{name: "user-password", in: "sip:alice:secret@example.com", wantRet: SGSIPRetOK, addr: "example.com", port: "5060", proto: "udp"},
		{name: "empty-user", in: "sip:@example.com", wantRet: SGSIPRetErrURIUser},
		{name: "bad-port", in: "sip:example.com:0", wantRet: SGSIPRetErrURIPort},
		{name: "bad-transport", in: "sip:example.com:5060;transport=bad", wantRet: SGSIPRetErrURIProto},
		{name: "empty", in: "", wantRet: SGSIPRetErrURI},
		{name: "empty-address", in: "sip:", wantRet: SGSIPRetErrURI},
		{name: "empty-host", in: "sip:alice@", wantRet: SGSIPRetErrURIFormat},
		{name: "host-port-empty-host", in: "sip::5060", wantRet: SGSIPRetErrURIFormat},
		{name: "empty-port", in: "sip:example.com:", wantRet: SGSIPRetErrURIPort},
		{name: "unterminated-ipv6", in: "sip:[::1", wantRet: SGSIPRetErrURIAFIPv6},
		{name: "lone-ipv6-bracket", in: "sip:[", wantRet: SGSIPRetErrURIAFIPv6},
		{name: "invalid-bracketed-host", in: "sip:[example.com]", wantRet: SGSIPRetErrURIAFIPv6},
		{name: "invalid-ipv6-suffix", in: "sip:[::1]broken", wantRet: SGSIPRetErrURIFormat},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var uri SGSIPURI
			ret := SGSIPParseURI(tc.in, &uri)
			if ret != tc.wantRet {
				t.Fatalf("unexpected return: got=%d want=%d", ret, tc.wantRet)
			}
			if ret == SGSIPRetOK {
				if uri.Addr != tc.addr || uri.Port != tc.port || uri.Proto != tc.proto {
					t.Fatalf("unexpected parsed uri: %+v", uri)
				}
			}
		})
	}
}

func TestURIAndSocketConversions(t *testing.T) {
	uri := SGSIPURI{Proto: "tcp", ProtoId: ProtoTCP, Addr: "example.com", Port: "5090", PortNo: 5090}
	var sa SGSIPSocketAddress
	if ret := SGSIPURIToSocketAddress(&uri, &sa); ret != SGSIPRetOK {
		t.Fatalf("SGSIPURIToSocketAddress failed: %d", ret)
	}
	if sa.Val != "tcp:example.com:5090" {
		t.Fatalf("unexpected socket value: %q", sa.Val)
	}

	secureURI := SGSIPURI{Schema: "sips", SchemaId: SchemaSIPS, Addr: "secure.example.com", AType: AFHost}
	if ret := SGSIPURIToSocketAddress(&secureURI, &sa); ret != SGSIPRetOK {
		t.Fatalf("SIPS URI conversion failed: %d", ret)
	}
	if sa.Val != "tls:secure.example.com:5061" || sa.ProtoId != ProtoTLS || sa.PortNo != 5061 {
		t.Fatalf("unexpected SIPS socket value: %+v", sa)
	}

	sa = SGSIPSocketAddress{Proto: "udp", ProtoId: ProtoUDP, Addr: "example.com", Port: "5060", PortNo: 5060}
	var outURI SGSIPURI
	if ret := SGSocketAddressToSIPURI(&sa, "alice", 0, &outURI); ret != SGSIPRetOK {
		t.Fatalf("SGSocketAddressToSIPURI failed: %d", ret)
	}
	if outURI.Val != "sip:alice@example.com:5060" {
		t.Fatalf("unexpected uri value: %q", outURI.Val)
	}
	if ret := SGSocketAddressToSIPURI(&sa, "alice", 1, &outURI); ret != SGSIPRetOK {
		t.Fatalf("SGSocketAddressToSIPURI failed: %d", ret)
	}
	if outURI.Val != "sip:alice@example.com:5060;transport=udp" {
		t.Fatalf("unexpected transport uri value: %q", outURI.Val)
	}
}

func TestParamsGet(t *testing.T) {
	var p SGSIPParam
	if ret := SGSIPParamsGet("line=44;transport=tls", "line", 0, &p); ret != SGSIPRetOK {
		t.Fatalf("expected param parse success, ret=%d", ret)
	}
	if p.Value != "44" || p.PMode != ParamValBare {
		t.Fatalf("unexpected param parse result: %+v", p)
	}

	if ret := SGSIPParamsGet("line=\"44\";transport=tls", "line", 1, &p); ret != SGSIPRetOK {
		t.Fatalf("expected quoted param parse success, ret=%d", ret)
	}
	if strings.Trim(p.Value, "\"") != "44" || p.PMode != ParamValQuoted {
		t.Fatalf("unexpected quoted param parse result: %+v", p)
	}

	if ret := SGSIPParamsGet("line=\"44\";transport=tls", "line", 0, &p); ret != SGSIPRetErrParamFormat {
		t.Fatalf("expected quoted param format error, ret=%d", ret)
	}
	if ret := SGSIPParamsGet("transport=tls", "line", 0, &p); ret != SGSIPRetErrParamNotFound {
		t.Fatalf("expected param not found, ret=%d", ret)
	}
}

func TestParseFirstLine(t *testing.T) {
	var fl SGSIPFirstLine
	if ret := SGSIPParseFirstLine("INVITE sip:alice@example.com SIP/2.0\r\n", &fl); ret != SGSIPRetOK {
		t.Fatalf("request first line parse failed: %d", ret)
	}
	if fl.MType != FLineRequest || fl.Method != "INVITE" || fl.URI != "sip:alice@example.com" {
		t.Fatalf("unexpected request first line parse: %+v", fl)
	}

	if ret := SGSIPParseFirstLine("SIP/2.0 200 OK\r\n", &fl); ret != SGSIPRetOK {
		t.Fatalf("response first line parse failed: %d", ret)
	}
	if fl.MType != FLineResponse || fl.Code != 200 || fl.Reason != "OK" {
		t.Fatalf("unexpected response first line parse: %+v", fl)
	}

	if ret := SGSIPParseFirstLine("SIP/2.0 a00 Bad\r\n", &fl); ret != SGSIPRetErrFLineResponseCode {
		t.Fatalf("expected response code error, got: %d", ret)
	}
}

func TestHeaderHelpersAndParsing(t *testing.T) {
	if SGSIPHeaderValidName("X-Test-1") != true {
		t.Fatalf("expected valid header name")
	}
	if SGSIPHeaderValidName("-Bad") != false {
		t.Fatalf("expected invalid header name")
	}
	if SGSIPHeaderGetType("v") != HeaderTypeVia || SGSIPHeaderGetType("cseq") != HeaderTypeCSeq {
		t.Fatalf("unexpected header type mapping")
	}

	raw := "Via: SIP/2.0/UDP host;branch=z9hG4bKSG.abc\r\nSubject: first\r\n second\r\nCSeq: 10 INVITE\r\n\r\n"
	var hdrs []SGSIPHeader
	if ret := SGSIPParseHeaders(raw, 1, &hdrs); ret != SGSIPRetOK {
		t.Fatalf("header parse failed: %d", ret)
	}
	if len(hdrs) != 3 {
		t.Fatalf("expected 3 headers, got: %d", len(hdrs))
	}
	if !strings.Contains(hdrs[1].Body, "second") {
		t.Fatalf("expected folded header body, got: %q", hdrs[1].Body)
	}

	var b SGSIPBody
	if ret := SGSIPParseBody("H: x\r\n\r\nbody", &b); ret != SGSIPRetOK || b.Content != "body" {
		t.Fatalf("body parse failed ret=%d body=%q", ret, b.Content)
	}
	if ret := SGSIPParseBody("H: x", &b); ret != SGSIPRetErrBody {
		t.Fatalf("expected body error, got: %d", ret)
	}
}

func TestMessageHeaderAndContactHelpers(t *testing.T) {
	msg := SGSIPMessage{
		Headers: []SGSIPHeader{
			{Name: "Contact", Body: "<sip:alice@example.com>;expires=60", HType: HeaderTypeContact},
		},
	}
	if ret := SGSIPMessageHeaderSet(&msg, "Contact", "<sip:bob@example.com>"); ret != SGSIPRetOK {
		t.Fatalf("header set failed: %d", ret)
	}
	var hb string
	if ret := SGSIPMessageHeaderGet(&msg, "Contact", &hb); ret != SGSIPRetOK || hb != "<sip:bob@example.com>" {
		t.Fatalf("header get failed ret=%d body=%q", ret, hb)
	}
	if ret := SGSIPMessageHeaderGet(&msg, "X-Missing", &hb); ret != SGSIPRetNotFound {
		t.Fatalf("expected not found for missing header, got: %d", ret)
	}

	var cturi string
	if ret := SGSIPMessageGetContactURI(&msg, &cturi); ret != SGSIPRetOK || cturi != "sip:bob@example.com" {
		t.Fatalf("unexpected contact uri ret=%d uri=%q", ret, cturi)
	}
}

func TestCSeqAndViaUpdates(t *testing.T) {
	msg := mustParseMessage(t, "INVITE sip:alice@example.com SIP/2.0\r\nVia: SIP/2.0/UDP host;branch=z9hG4bKSG.abc;rport\r\nFrom: <sip:alice@example.com>;tag=1\r\nTo: <sip:bob@example.com>\r\nCall-ID: 1\r\nCSeq: 10 INVITE\r\nContent-Length: 0\r\n\r\n")

	if ret := SGSIPMessageCSeqParse(&msg); ret != SGSIPRetOK || msg.CSeq.Number != 10 {
		t.Fatalf("cseq parse failed ret=%d cseq=%+v", ret, msg.CSeq)
	}
	if ret := SGSIPMessageCSeqUpdate(&msg, 2); ret != SGSIPRetOK {
		t.Fatalf("cseq update failed: %d", ret)
	}
	var cseqBody string
	_ = SGSIPMessageHeaderGet(&msg, "CSeq", &cseqBody)
	if cseqBody != "12 INVITE" {
		t.Fatalf("unexpected cseq update body: %q", cseqBody)
	}

	if ret := SGSIPMessageViaUpdate(&msg); ret != SGSIPRetOK {
		t.Fatalf("via update failed: %d", ret)
	}
	var viaBody string
	_ = SGSIPMessageHeaderGet(&msg, "Via", &viaBody)
	if !strings.Contains(viaBody, ";branch=z9hG4bKSG.") {
		t.Fatalf("unexpected via branch after update: %q", viaBody)
	}
}

func TestParseMessageAndMessageToString(t *testing.T) {
	raw := "MESSAGE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP host;branch=z9hG4bKSG.a\r\nFrom: <sip:alice@example.com>;tag=1\r\nTo: <sip:bob@example.com>\r\nCall-ID: abc\r\nCSeq: 1 MESSAGE\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello"
	msg := SGSIPMessage{}
	if ret := SGSIPParseMessage(raw, &msg); ret != SGSIPRetOK {
		t.Fatalf("parse message failed: %d", ret)
	}
	if msg.CSeq.Number != 1 || msg.Body.Content != "hello" {
		t.Fatalf("unexpected parsed message fields: cseq=%+v body=%q", msg.CSeq, msg.Body.Content)
	}

	out := ""
	if ret := SGSIPMessageToString(&msg, &out); ret != SGSIPRetOK {
		t.Fatalf("message to string failed: %d", ret)
	}
	if !strings.HasPrefix(out, "MESSAGE sip:bob@example.com SIP/2.0\r\n") {
		t.Fatalf("unexpected output first line: %q", out)
	}
	if !strings.Contains(out, "\r\n\r\nhello") {
		t.Fatalf("expected message body in output: %q", out)
	}
}

func TestParseMessageHonorsContentLength(t *testing.T) {
	message := func(headers string, body string) string {
		return "MESSAGE sip:bob@example.com SIP/2.0\r\n" +
			"Via: SIP/2.0/UDP host;branch=z9hG4bKSG.a\r\n" +
			"From: <sip:alice@example.com>;tag=1\r\n" +
			"To: <sip:bob@example.com>\r\n" +
			"Call-ID: abc\r\n" +
			"CSeq: 1 MESSAGE\r\n" + headers + "\r\n" + body
	}

	tests := []struct {
		name        string
		headers     string
		body        string
		wantRet     int
		wantContent string
	}{
		{name: "exact", headers: "Content-Length: 5\r\n", body: "hello", wantRet: SGSIPRetOK, wantContent: "hello"},
		{name: "trims trailing data", headers: "Content-Length: 5\r\n", body: "helloNEXT", wantRet: SGSIPRetOK, wantContent: "hello"},
		{name: "zero ignores trailing data", headers: "Content-Length: 0\r\n", body: "NEXT", wantRet: SGSIPRetOK, wantContent: ""},
		{name: "compact header", headers: "l: 4\r\n", body: "testNEXT", wantRet: SGSIPRetOK, wantContent: "test"},
		{name: "byte length", headers: "Content-Length: 2\r\n", body: "\xc3\xa9NEXT", wantRet: SGSIPRetOK, wantContent: "\xc3\xa9"},
		{name: "missing header means zero", headers: "Content-Type: text/plain\r\n", body: "ignored", wantRet: SGSIPRetOK, wantContent: ""},
		{name: "truncated", headers: "Content-Length: 6\r\n", body: "short", wantRet: SGSIPRetErrBody},
		{name: "malformed", headers: "Content-Length: invalid\r\n", wantRet: SGSIPRetErrBody},
		{name: "negative", headers: "Content-Length: -1\r\n", wantRet: SGSIPRetErrBody},
		{name: "signed", headers: "Content-Length: +1\r\n", body: "x", wantRet: SGSIPRetErrBody},
		{name: "matching duplicates", headers: "Content-Length: 4\r\nl: 4\r\n", body: "test", wantRet: SGSIPRetOK, wantContent: "test"},
		{name: "conflicting duplicates", headers: "Content-Length: 4\r\nl: 5\r\n", body: "tests", wantRet: SGSIPRetErrBody},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var msg SGSIPMessage
			ret := SGSIPParseMessage(message(tc.headers, tc.body), &msg)
			if ret != tc.wantRet {
				t.Fatalf("expected return %d, got %d", tc.wantRet, ret)
			}
			if ret == SGSIPRetOK && (msg.Body.Content != tc.wantContent || msg.Body.ContentLen != len(tc.wantContent)) {
				t.Fatalf("unexpected body: content=%q length=%d", msg.Body.Content, msg.Body.ContentLen)
			}
		})
	}
}

func TestInviteToACKString(t *testing.T) {
	invReq := mustParseMessage(t, "INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP host;branch=z9hG4bKSG.req\r\nFrom: <sip:alice@example.com>;tag=f1\r\nTo: <sip:bob@example.com>\r\nCall-ID: c1\r\nCSeq: 10 INVITE\r\nAuthorization: Digest user=\"alice\"\r\nContent-Length: 0\r\n\r\n")
	invRpl2xx := mustParseMessage(t, "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP host;branch=z9hG4bKSG.req\r\nFrom: <sip:alice@example.com>;tag=f1\r\nTo: <sip:bob@example.com>;tag=t1\r\nCall-ID: c1\r\nCSeq: 10 INVITE\r\nContact: <sip:bob@contact.example.com>\r\nRecord-Route: <sip:rr1.example.com;lr>,<sip:rr2.example.com;lr>\r\nContent-Length: 0\r\n\r\n")
	out := ""
	if ret := SGSIPInviteToACKString(&invReq, &invRpl2xx, &out); ret != SGSIPRetOK {
		t.Fatalf("invite->ack failed: %d", ret)
	}
	if !strings.HasPrefix(out, "ACK sip:bob@contact.example.com SIP/2.0\r\n") {
		t.Fatalf("unexpected ack request-uri: %q", out)
	}
	if !strings.Contains(out, "CSeq: 10 ACK\r\n") {
		t.Fatalf("expected CSeq ACK in output: %q", out)
	}
	if !strings.Contains(out, "Route: <sip:rr2.example.com;lr>\r\nRoute: <sip:rr1.example.com;lr>\r\n") {
		t.Fatalf("expected reversed Record-Route mapping in output: %q", out)
	}
	if !regexp.MustCompile(`Via: .*;branch=z9hG4bKSG\.[^\r\n]+`).MatchString(out) {
		t.Fatalf("expected regenerated via branch in ack: %q", out)
	}

	invRpl3xx := mustParseMessage(t, "SIP/2.0 404 Not Found\r\nVia: SIP/2.0/UDP host;branch=z9hG4bKSG.req\r\nFrom: <sip:alice@example.com>;tag=f1\r\nTo: <sip:bob@example.com>;tag=t1\r\nCall-ID: c1\r\nCSeq: 10 INVITE\r\nContent-Length: 0\r\n\r\n")
	if ret := SGSIPInviteToACKString(&invReq, &invRpl3xx, &out); ret != SGSIPRetOK {
		t.Fatalf("invite->ack (3xx+) failed: %d", ret)
	}
	if !strings.HasPrefix(out, "ACK sip:bob@example.com SIP/2.0\r\n") {
		t.Fatalf("expected original req-uri in non-2xx ack: %q", out)
	}
}

func TestACKToByeString(t *testing.T) {
	ackReq := mustParseMessage(t, "ACK sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP host;branch=z9hG4bKSG.ack\r\nFrom: <sip:alice@example.com>;tag=f1\r\nTo: <sip:bob@example.com>;tag=t1\r\nCall-ID: c1\r\nCSeq: 10 ACK\r\nRoute: <sip:proxy.example.com;lr>\r\nContent-Length: 0\r\n\r\n")
	out := ""
	if ret := SGSIPACKToByeString(&ackReq, &out); ret != SGSIPRetOK {
		t.Fatalf("ack->bye failed: %d", ret)
	}
	if !strings.HasPrefix(out, "BYE sip:bob@example.com SIP/2.0\r\n") {
		t.Fatalf("unexpected BYE first line: %q", out)
	}
	if !strings.Contains(out, "CSeq: 11 BYE\r\n") {
		t.Fatalf("expected incremented CSeq BYE: %q", out)
	}
	if !strings.Contains(out, "Route: <sip:proxy.example.com;lr>\r\n") {
		t.Fatalf("expected route in BYE: %q", out)
	}
}

func TestMessageToResponseString(t *testing.T) {
	req := mustParseMessage(t, "OPTIONS sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP host;branch=z9hG4bKSG.req\r\nFrom: <sip:alice@example.com>;tag=f1\r\nTo: <sip:bob@example.com>\r\nCall-ID: c1\r\nCSeq: 10 OPTIONS\r\nContent-Length: 0\r\n\r\n")
	out := ""
	if ret := SGSIPMessageToResponseString(&req, "200", "OK", &out); ret != SGSIPRetOK {
		t.Fatalf("message->response failed: %d", ret)
	}
	if !strings.HasPrefix(out, "SIP/2.0 200 OK\r\n") {
		t.Fatalf("unexpected response first line: %q", out)
	}
	if !regexp.MustCompile(`(?m)^To: .*;tag=[0-9a-f-]+$`).MatchString(strings.ReplaceAll(out, "\r", "")) {
		t.Fatalf("expected To-tag to be appended: %q", out)
	}
	if !strings.Contains(out, "Call-ID: c1\r\n") || !strings.Contains(out, "CSeq: 10 OPTIONS\r\n") {
		t.Fatalf("expected call-id and cseq in response: %q", out)
	}
}

func TestMessageToResponseStringReusesInviteToTag(t *testing.T) {
	req := mustParseMessage(t, "INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP host;branch=z9hG4bKSG.req\r\nFrom: <sip:alice@example.com>;tag=f1\r\nTo: <sip:bob@example.com>\r\nCall-ID: c1\r\nCSeq: 10 INVITE\r\nContent-Length: 0\r\n\r\n")

	responses := make(map[string]string)
	for _, response := range []struct {
		code   string
		reason string
	}{
		{code: "100", reason: "Trying"},
		{code: "180", reason: "Ringing"},
		{code: "200", reason: "OK"},
	} {
		out := ""
		if ret := SGSIPMessageToResponseString(&req, response.code, response.reason, &out); ret != SGSIPRetOK {
			t.Fatalf("message->%s response failed: %d", response.code, ret)
		}
		responses[response.code] = out
	}

	tagPattern := regexp.MustCompile(`(?m)^To: .*;tag=([^;\r\n]+)`)
	if tagPattern.MatchString(responses["100"]) {
		t.Fatalf("100 Trying must not create a To-tag: %q", responses["100"])
	}
	tag180 := tagPattern.FindStringSubmatch(responses["180"])
	tag200 := tagPattern.FindStringSubmatch(responses["200"])
	if len(tag180) != 2 || len(tag200) != 2 {
		t.Fatalf("expected 180 and 200 responses to contain To-tags: 180=%q 200=%q", responses["180"], responses["200"])
	}
	if tag180[1] != tag200[1] {
		t.Fatalf("expected the same To-tag, got 180=%q 200=%q", tag180[1], tag200[1])
	}
}

func TestMessageToResponseStringInviteRecordRoute(t *testing.T) {
	reqWithRR := mustParseMessage(t, "INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP host;branch=z9hG4bKSG.req\r\nFrom: <sip:alice@example.com>;tag=f1\r\nTo: <sip:bob@example.com>\r\nCall-ID: c1\r\nCSeq: 10 INVITE\r\nRecord-Route: <sip:rr1.example.com;lr>\r\nRecord-Route: <sip:rr2.example.com;lr>\r\nContent-Length: 0\r\n\r\n")
	reqOptionsWithRR := mustParseMessage(t, "OPTIONS sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP host;branch=z9hG4bKSG.req\r\nFrom: <sip:alice@example.com>;tag=f1\r\nTo: <sip:bob@example.com>\r\nCall-ID: c2\r\nCSeq: 11 OPTIONS\r\nRecord-Route: <sip:rr.example.com;lr>\r\nContent-Length: 0\r\n\r\n")

	tests := []struct {
		name         string
		req          SGSIPMessage
		scode        string
		wantContains []string
		wantAbsent   []string
	}{
		{
			name:         "invite-180-includes-record-route",
			req:          reqWithRR,
			scode:        "180",
			wantContains: []string{"Record-Route: <sip:rr1.example.com;lr>\r\n", "Record-Route: <sip:rr2.example.com;lr>\r\n"},
		},
		{
			name:         "invite-200-includes-record-route",
			req:          reqWithRR,
			scode:        "200",
			wantContains: []string{"Record-Route: <sip:rr1.example.com;lr>\r\n", "Record-Route: <sip:rr2.example.com;lr>\r\n"},
		},
		{
			name:       "invite-100-does-not-include-record-route",
			req:        reqWithRR,
			scode:      "100",
			wantAbsent: []string{"Record-Route: <sip:rr1.example.com;lr>\r\n", "Record-Route: <sip:rr2.example.com;lr>\r\n"},
		},
		{
			name:       "non-invite-200-does-not-include-record-route",
			req:        reqOptionsWithRR,
			scode:      "200",
			wantAbsent: []string{"Record-Route: <sip:rr.example.com;lr>\r\n"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := ""
			if ret := SGSIPMessageToResponseString(&tc.req, tc.scode, "Test", &out); ret != SGSIPRetOK {
				t.Fatalf("message->response failed: %d", ret)
			}
			for _, expected := range tc.wantContains {
				if !strings.Contains(out, expected) {
					t.Fatalf("expected response to include %q; output: %q", expected, out)
				}
			}
			for _, unexpected := range tc.wantAbsent {
				if strings.Contains(out, unexpected) {
					t.Fatalf("expected response to not include %q; output: %q", unexpected, out)
				}
			}
		})
	}
}

func TestHeaderParseDigestAuthBodyCaseInsensitiveScheme(t *testing.T) {
	params := SGSIPHeaderParseDigestAuthBody(`digest realm="example.com", nonce="abc", algorithm=SHA-256`)
	if params == nil {
		t.Fatalf("expected digest auth params map, got nil")
	}
	if params["realm"] != "example.com" || params["nonce"] != "abc" || params["algorithm"] != "SHA-256" {
		t.Fatalf("unexpected parsed params: %#v", params)
	}
}

func FuzzSGSIPAddressParsersDoNotPanic(f *testing.F) {
	for _, seed := range []string{
		"",
		":",
		"tcp:",
		"tcp:[::1",
		"tcp:[::1]",
		"sip:",
		"sip:[",
		"sip:[::1",
		"sip:alice@",
		"sip:alice:secret@example.com",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		_ = SGAddrTypeEx(input)
		_ = SGSIPParseSocketAddress(input, &SGSIPSocketAddress{})
		_ = SGSIPParseURI(input, &SGSIPURI{})
	})
}

package sgsip

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

func TestHashHelpers(t *testing.T) {
	input := "abc"

	if got := SGHashMD5(input); got != fmt.Sprintf("%x", md5.Sum([]byte(input))) {
		t.Fatalf("SGHashMD5 mismatch: %s", got)
	}
	if got := SGHashSHA1(input); got != fmt.Sprintf("%x", sha1.Sum([]byte(input))) {
		t.Fatalf("SGHashSHA1 mismatch: %s", got)
	}
	if got := SGHashSHA256(input); got != fmt.Sprintf("%x", sha256.Sum256([]byte(input))) {
		t.Fatalf("SGHashSHA256 mismatch: %s", got)
	}
	if got := SGHashSHA512_256(input); got != fmt.Sprintf("%x", sha512.Sum512_256([]byte(input))) {
		t.Fatalf("SGHashSHA512_256 mismatch: %s", got)
	}
	if got := SGHashSHA512(input); got != fmt.Sprintf("%x", sha512.Sum512([]byte(input))) {
		t.Fatalf("SGHashSHA512 mismatch: %s", got)
	}

	if got := SGHashX("sha-256", input); got != SGHashSHA256(input) {
		t.Fatalf("SGHashX sha-256 mismatch: %s", got)
	}
	if got := SGHashX("unknown", input); got != SGHashMD5(input) {
		t.Fatalf("SGHashX fallback mismatch: %s", got)
	}

	if got := SGHashBytes("md5", []byte(input)); got != SGHashMD5(input) {
		t.Fatalf("SGHashBytes md5 mismatch: %s", got)
	}
	if got := SGHashBytes("sha256", []byte(input)); got != SGHashSHA256(input) {
		t.Fatalf("SGHashBytes sha256 mismatch: %s", got)
	}
	if got := SGHashBytes("unsupported", []byte(input)); got != SGHashMD5(input) {
		t.Fatalf("SGHashBytes fallback mismatch: %s", got)
	}
}

func TestNonceHelpers(t *testing.T) {
	nc := SGAuthGetNC(1)
	if nc != "00000001" {
		t.Fatalf("unexpected nc: %s", nc)
	}

	cn := SGCreateClientNonce(8)
	if len(cn) != 16 {
		t.Fatalf("unexpected nonce length: %d", len(cn))
	}
	if !regexp.MustCompile(`^[0-9a-f]+$`).MatchString(cn) {
		t.Fatalf("nonce is not lowercase hex: %s", cn)
	}
}

func TestSGAuthBuildResponseBody(t *testing.T) {
	hparams := map[string]string{
		"realm":  "example.com",
		"nonce":  "n123",
		"uri":    "sip:example.com",
		"method": "REGISTER",
		"qop":    "none",
	}

	body, err := SGAuthBuildResponseBody("alice", "secret", false, hparams)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(body, `Digest username="alice"`) ||
		!strings.Contains(body, `realm="example.com"`) ||
		!strings.Contains(body, `response="`) ||
		!strings.Contains(body, `algorithm=MD5`) {
		t.Fatalf("unexpected digest body for qop=none: %s", body)
	}

	hparams = map[string]string{
		"algorithm": "SHA-256",
		"realm":     "example.com",
		"nonce":     "n123",
		"uri":       "sip:example.com",
		"method":    "REGISTER",
		"qop":       "auth",
		"opaque":    "o1",
	}
	body, err = SGAuthBuildResponseBody("alice", "secret", false, hparams)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(body, `cnonce="`) ||
		!strings.Contains(body, `nc=00000001`) ||
		!strings.Contains(body, `qop=auth`) ||
		!strings.Contains(body, `algorithm=SHA-256`) {
		t.Fatalf("unexpected digest body for qop=auth: %s", body)
	}

	hparams["qop"] = "auth-int"
	hparams["body"] = "payload"
	body, err = SGAuthBuildResponseBody("alice", "secret", false, hparams)
	if err != nil {
		t.Fatalf("unexpected error for auth-int: %v", err)
	}
	if !strings.Contains(body, `qop=auth-int`) {
		t.Fatalf("missing auth-int qop: %s", body)
	}

	hparams["qop"] = "bad"
	if _, err = SGAuthBuildResponseBody("alice", "secret", false, hparams); err == nil {
		t.Fatalf("expected unsupported qop error")
	}

	hparams["qop"] = "auth"
	hparams["algorithm"] = "MD5"
	ha1 := SGHashMD5("alice:example.com:secret")
	body, err = SGAuthBuildResponseBody("alice", ha1, true, hparams)
	if err != nil {
		t.Fatalf("unexpected ha1mode error: %v", err)
	}
	if !strings.Contains(body, `response="`) {
		t.Fatalf("missing response in ha1mode body: %s", body)
	}
}

func TestAKAUtilityFunctions(t *testing.T) {
	rand := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	autn := []byte{16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}
	nonce := base64.StdEncoding.EncodeToString(append(rand, autn...))

	prand, pautn, err := SGAKAParseNonce(nonce)
	if err != nil {
		t.Fatalf("unexpected parse nonce error: %v", err)
	}
	if SGAKACompareBytes(prand, rand) != 0 || SGAKACompareBytes(pautn, autn) != 0 {
		t.Fatalf("parsed RAND/AUTN mismatch")
	}
	if _, _, err = SGAKAParseNonce("%%%"); err == nil {
		t.Fatalf("expected decode error for bad nonce")
	}
	short := base64.StdEncoding.EncodeToString(make([]byte, 31))
	if _, _, err = SGAKAParseNonce(short); err == nil {
		t.Fatalf("expected short nonce length error")
	}

	if SGAKACompareBytes([]byte{1}, []byte{1, 2}) != -2 {
		t.Fatalf("unexpected compare result for shorter left value")
	}
	if SGAKACompareBytes([]byte{1, 2}, []byte{1}) != 2 {
		t.Fatalf("unexpected compare result for longer left value")
	}
	if SGAKACompareBytes([]byte{1, 2}, []byte{1, 3}) != -1 {
		t.Fatalf("unexpected compare result for lexicographically lower value")
	}
	if SGAKACompareBytes([]byte{1, 4}, []byte{1, 3}) != 1 {
		t.Fatalf("unexpected compare result for lexicographically higher value")
	}

	xv := SGAKAXor([]byte{0xff, 0x0f, 0x55}, []byte{0x0f, 0xf0})
	if len(xv) != 2 || xv[0] != 0xf0 || xv[1] != 0xff {
		t.Fatalf("unexpected xor result: %v", xv)
	}
}

func TestAKAComputeFunctions(t *testing.T) {
	key := []byte{0x46, 0x5b, 0x5c, 0xe8, 0xb1, 0x99, 0xb4, 0x9f, 0xaa, 0x5f, 0x0a, 0x2e, 0xe2, 0x38, 0xa6, 0xbc}
	op := []byte{0xcd, 0xc2, 0x02, 0xd5, 0x12, 0x3e, 0x20, 0xf6, 0x2b, 0x6d, 0x67, 0x6a, 0xc7, 0x2c, 0xb3, 0x18}
	rand := []byte{0x23, 0x55, 0x3c, 0xbe, 0x96, 0x37, 0xa8, 0x9d, 0x21, 0x8a, 0xe6, 0x4d, 0xae, 0x47, 0xbf, 0x35}
	sqn := []byte{0xff, 0x9b, 0xb4, 0xd0, 0xb6, 0x07}
	amf := []byte{0x80, 0x00}

	opc, err := SGAKAComputeOPc(key, op)
	if err != nil {
		t.Fatalf("unexpected opc error: %v", err)
	}
	if len(opc) != 16 {
		t.Fatalf("unexpected opc length: %d", len(opc))
	}

	enc, err := SGAKAEncrypt(key, rand)
	if err != nil {
		t.Fatalf("unexpected encrypt error: %v", err)
	}
	if len(enc) != 16 {
		t.Fatalf("unexpected encrypted length: %d", len(enc))
	}

	mac, err := SGAKAComputeF1(key, op, nil, rand, sqn, amf)
	if err != nil {
		t.Fatalf("unexpected f1 error: %v", err)
	}
	if len(mac) != 8 {
		t.Fatalf("unexpected mac length: %d", len(mac))
	}

	res, ck, ik, ak, err := SGAKAComputeF2345(key, op, nil, rand)
	if err != nil {
		t.Fatalf("unexpected f2345 error: %v", err)
	}
	if len(res) != 8 || len(ck) != 16 || len(ik) != 16 || len(ak) != 6 {
		t.Fatalf("unexpected f2345 sizes res=%d ck=%d ik=%d ak=%d", len(res), len(ck), len(ik), len(ak))
	}

	if _, err := SGAKAEncrypt([]byte{1, 2, 3}, rand); err == nil {
		t.Fatalf("expected invalid key size error")
	}
}

func buildValidAKAChallenge(t *testing.T, key, op, amf []byte) map[string]string {
	t.Helper()

	rand := []byte{0x23, 0x55, 0x3c, 0xbe, 0x96, 0x37, 0xa8, 0x9d, 0x21, 0x8a, 0xe6, 0x4d, 0xae, 0x47, 0xbf, 0x35}
	sqn := []byte{0xff, 0x9b, 0xb4, 0xd0, 0xb6, 0x07}

	_, _, _, ak, err := SGAKAComputeF2345(key, op, nil, rand)
	if err != nil {
		t.Fatalf("failed to compute AK: %v", err)
	}
	xsqn := SGAKAXor(sqn, ak)
	mac, err := SGAKAComputeF1(key, op, nil, rand, sqn, amf)
	if err != nil {
		t.Fatalf("failed to compute MAC: %v", err)
	}
	autn := make([]byte, 16)
	copy(autn[0:6], xsqn)
	copy(autn[6:8], amf)
	copy(autn[8:16], mac)

	nonce := base64.StdEncoding.EncodeToString(append(rand, autn...))
	return map[string]string{
		"algorithm": "AKAv1-MD5",
		"nonce":     nonce,
		"realm":     "example.com",
		"method":    "REGISTER",
		"qop":       "auth",
		"uri":       "sip:example.com",
	}
}

func TestSGAKAHandleChallenge(t *testing.T) {
	key := []byte{0x46, 0x5b, 0x5c, 0xe8, 0xb1, 0x99, 0xb4, 0x9f, 0xaa, 0x5f, 0x0a, 0x2e, 0xe2, 0x38, 0xa6, 0xbc}
	op := []byte{0xcd, 0xc2, 0x02, 0xd5, 0x12, 0x3e, 0x20, 0xf6, 0x2b, 0x6d, 0x67, 0x6a, 0xc7, 0x2c, 0xb3, 0x18}
	amf := []byte{0x80, 0x00}

	ch := buildValidAKAChallenge(t, key, op, amf)
	h, err := SGAKAHandleChallenge("alice", key, op, nil, amf, ch)
	if err != nil {
		t.Fatalf("unexpected AKA challenge handling error: %v", err)
	}
	if !strings.Contains(h, `Digest username="alice"`) ||
		!strings.Contains(h, `realm="example.com"`) ||
		!strings.Contains(h, `uri="sip:example.com"`) ||
		!strings.Contains(h, `algorithm=AKAv1-MD5`) ||
		!strings.Contains(h, `qop=auth`) ||
		!strings.Contains(h, `nc=00000001`) ||
		!strings.Contains(h, `response="`) {
		t.Fatalf("unexpected AKA auth header: %s", h)
	}
	if len(ch["ck"]) != 32 || len(ch["ik"]) != 32 {
		t.Fatalf("expected ck/ik to be set as hex strings, ck=%q ik=%q", ch["ck"], ch["ik"])
	}

	if _, err = SGAKAHandleChallenge("alice", key, op, nil, amf, map[string]string{}); err == nil {
		t.Fatalf("expected missing params error")
	}

	badNonce := map[string]string{
		"algorithm": "AKAv1-MD5",
		"nonce":     "%%%bad%%%nonce",
		"realm":     "example.com",
		"method":    "REGISTER",
		"qop":       "auth",
	}
	if _, err = SGAKAHandleChallenge("alice", key, op, nil, amf, badNonce); err == nil {
		t.Fatalf("expected bad nonce error")
	}

	chAMF := buildValidAKAChallenge(t, key, op, amf)
	if _, err = SGAKAHandleChallenge("alice", key, op, nil, []byte{0x00, 0x00}, chAMF); err == nil {
		t.Fatalf("expected amf mismatch error")
	}

	chXMAC := buildValidAKAChallenge(t, key, op, amf)
	dec, _ := base64.StdEncoding.DecodeString(chXMAC["nonce"])
	dec[31] ^= 0xff
	chXMAC["nonce"] = base64.StdEncoding.EncodeToString(dec)
	if _, err = SGAKAHandleChallenge("alice", key, op, nil, amf, chXMAC); err == nil {
		t.Fatalf("expected xmac mismatch error")
	}

	chBadKey := buildValidAKAChallenge(t, key, op, amf)
	if _, err = SGAKAHandleChallenge("alice", []byte{1, 2, 3}, op, nil, amf, chBadKey); err == nil {
		t.Fatalf("expected invalid key error")
	}
}


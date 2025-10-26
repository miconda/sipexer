// SIPExer Generic SIP Parsing Library - Auth Digest and AKA helper functions
package sgsip

import (
	"bytes"
	"crypto/aes"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// SGHashMD5 - return a lower-case hex MD5 digest of the parameter
func SGHashMD5(data string) string {
	md5d := md5.New()
	md5d.Write([]byte(data))
	return fmt.Sprintf("%x", md5d.Sum(nil))
}

// SGHashSHA1 - return a lower-case hex SHA1 digest of the parameter
func SGHashSHA1(data string) string {
	h := sha1.New()
	h.Write([]byte(data))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// SGHashSHA256 - return a lower-case hex SHA256 digest of the parameter
func SGHashSHA256(data string) string {
	h := sha256.New()
	h.Write([]byte(data))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// SGHashSHA512_256 - return a lower-case hex SHA512-256 digest of the parameter
func SGHashSHA512_256(input string) string {
	h := sha512.New512_256()
	h.Write([]byte(input))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// SGHashSHA512 - return a lower-case hex SHA512 digest of the parameter
func SGHashSHA512(input string) string {
	h := sha512.New()
	h.Write([]byte(input))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// SGHashX - return a lower-case hex of the hashed parameter
func SGHashX(sAlg string, sData string) string {
	sHash := ""
	switch strings.ToLower(strings.Replace(sAlg, "-", "", 2)) {
	case "sha1":
		sHash = SGHashSHA1(sData)
	case "sha256":
		sHash = SGHashSHA256(sData)
	case "sha512256":
		sHash = SGHashSHA512_256(sData)
	case "sha512":
		sHash = SGHashSHA512(sData)
	default:
		sHash = SGHashMD5(sData)
	}
	return sHash
}

// SGClientNonce generates a client nonce
func SGCreateClientNonce(cnsize int) string {
	// Create a byte slice to hold the random data
	b := make([]byte, cnsize)

	// Read cryptographically secure random bytes
	if _, err := rand.Read(b); err != nil {
		return ""
	}

	// Encode the random bytes as a hexadecimal string
	return hex.EncodeToString(b)
}

// SGAuthBuildResponseBody - return the body for auth header in response
func SGAuthBuildResponseBody(username string, password string, ha1mode bool, hparams map[string]string) (string, error) {
	// https://en.wikipedia.org/wiki/Digest_access_authentication

	vAlg, ok := hparams["algorithm"]
	if !ok {
		vAlg = "MD5"
	}
	vQop, ok := hparams["qop"]
	if !ok {
		vQop = "none"
	} else {
		vQop = strings.ToLower(vQop)
	}
	if vQop != "none" && vQop != "auth" && vQop != "auth-int" {
		return "", fmt.Errorf("unsupported qop value: %s", vQop)
	}
	sHA1 := ""
	if ha1mode {
		sHA1 = password
	} else {
		sHA1 = SGHashX(vAlg, username+":"+hparams["realm"]+":"+password)
	}

	var AuthHeader string
	var sHA2 string

	if vQop == "none" {
		sHA2 = SGHashX(vAlg, hparams["method"]+":"+hparams["uri"])
		// build digest response
		response := SGHashX(vAlg, sHA1+":"+hparams["nonce"]+":"+sHA2)
		// build header body
		AuthHeader = fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", algorithm=MD5, response="%s"`,
			username, hparams["realm"], hparams["nonce"], hparams["uri"], response)
	} else {
		if vQop == "auth" {
			sHA2 = SGHashX(vAlg, hparams["method"]+":"+hparams["uri"])
		} else {
			vBody, ok := hparams["body"]
			if !ok {
				vBody = ""
			}
			sHA2 = SGHashX(vAlg, hparams["method"]+":"+hparams["uri"]+":"+SGHashX(vAlg, vBody))
		}
		// build digest response
		cnonce := SGCreateClientNonce(6)
		response := ""
		if strings.ToLower(hparams["qop"]) != "auth" {
			response = SGHashX(vAlg, sHA1+":"+hparams["nonce"]+":"+"00000001"+":"+cnonce+":"+hparams["qop"]+":"+sHA2)
		} else {
		}
		// build header body
		AuthHeader = fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", cnonce="%s", nc=00000001, qop=%s, opaque="%s", algorithm=MD5, response="%s"`,
			username, hparams["realm"], hparams["nonce"], hparams["uri"], cnonce, hparams["qop"], hparams["opaque"], response)
	}
	return AuthHeader, nil
}

// SGAKAParseNonce parses the base64-encoded nonce containing RAND and AUTN
func SGAKAParseNonce(nonceStr string) ([]byte, []byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(nonceStr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode nonce: %w", err)
	}

	// RAND is first 16 bytes, AUTN is next 16 bytes
	if len(decoded) < 32 {
		return nil, nil, errors.New("invalid nonce length")
	}

	rand := decoded[:16]
	autn := decoded[16:32]

	return rand, autn, nil
}

// SGAKACompareBytes compares to byte arrays
func SGAKACompareBytes(v1, v2 []byte) int {
	if len(v1) < len(v2) {
		return -2
	}
	if len(v1) > len(v2) {
		return 2
	}
	for i := 0; i < len(v1); i++ {
		if v1[i] < v2[i] {
			return -1
		}
		if v1[i] > v2[i] {
			return 1
		}
	}
	return 0
}

// SGAKAXor performs XOR with bytes of two arrays, returning a new array
func SGAKAXor(v1, v2 []byte) []byte {
	var lv int
	if len(v1) < len(v2) {
		lv = len(v1)
	} else {
		lv = len(v2)
	}

	out := make([]byte, lv)
	for i := 0; i < lv; i++ {
		out[i] = v1[i] ^ v2[i]
	}
	return out
}

// SGAKAComputeOPc computes OPc from K and OP inside m.
func SGAKAComputeOPc(K, OP []byte) ([]byte, error) {
	OPc := make([]byte, 16)

	block, err := aes.NewCipher(K)
	if err != nil {
		return nil, err
	}
	eData := make([]byte, len(OP))
	block.Encrypt(eData, OP)

	xBytes := SGAKAXor(eData, OP)
	for i, b := range xBytes {
		if i > len(OPc) {
			break
		}
		OPc[i] = b
	}
	return OPc, nil
}

// SGAKAEncrypt encrypts text with key using AES cipher
func SGAKAEncrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	eBytes := make([]byte, len(text))
	block.Encrypt(eBytes, text)
	return eBytes, nil
}

// SGAKAComputeF1Base computes the first base for F1
func SGAKAComputeF1Base(K, OP, OPC, RAND, sqn, amf []byte) ([]byte, error) {
	var OPcV []byte
	var err error

	if OPC == nil {
		OPcV, err = SGAKAComputeOPc(K, OP)
		if err != nil {
			return nil, err
		}
	} else {
		OPcV = OPC
	}

	eData := make([]byte, 16)
	for i := 0; i < 16; i++ {
		eData[i] = RAND[i] ^ OPcV[i]
	}

	tmp, err := SGAKAEncrypt(K, eData)
	if err != nil {
		return nil, err
	}

	in1 := make([]byte, 16)
	for i := 0; i < 6; i++ {
		in1[i] = sqn[i]
		in1[i+8] = sqn[i]
	}
	for i := 0; i < 2; i++ {
		in1[i+6] = amf[i]
		in1[i+14] = amf[i]
	}

	for i := 0; i < 16; i++ {
		eData[(i+8)%16] = in1[i] ^ OPcV[i]
	}

	for i := 0; i < 16; i++ {
		eData[i] ^= tmp[i]
	}

	out, err := SGAKAEncrypt(K, eData)
	if err != nil {
		return nil, err
	}

	return SGAKAXor(out, OPcV), nil
}

// SGAKAComputeF1 computes the F1
func SGAKAComputeF1(K, OP, OPC, RAND, SQN, AMF []byte) ([]byte, error) {
	mac, err := SGAKAComputeF1Base(K, OP, OPC, RAND, SQN, AMF)
	if err != nil {
		return nil, err
	}

	return mac[:8], nil
}

// SGAKAComputeF2345 computes F2/3/4/5
func SGAKAComputeF2345(K, OP, OPC, RAND []byte) (res, ck, ik, ak []byte, errv error) {
	var OPcV []byte
	var err error

	if OPC == nil {
		OPcV, err = SGAKAComputeOPc(K, OP)
		if err != nil {
			return nil, nil, nil, nil, err
		}
	} else {
		OPcV = OPC
	}

	eData := make([]byte, 16)
	for i := 0; i < 16; i++ {
		eData[i] = RAND[i] ^ OPcV[i]
	}

	tmp, err := SGAKAEncrypt(K, eData)
	if err != nil {
		return
	}

	for i := 0; i < 16; i++ {
		eData[i] = tmp[i] ^ OPcV[i]
	}
	eData[15] ^= 1

	out, err := SGAKAEncrypt(K, eData)
	if err != nil {
		return
	}
	tv := SGAKAXor(out, OPcV)
	res = tv[8:]
	ak = tv[:6]

	for i := 0; i < 16; i++ {
		eData[(i+12)%16] = tmp[i] ^ OPcV[i]
	}
	eData[15] ^= 2

	out, err = SGAKAEncrypt(K, eData)
	if err != nil {
		return
	}
	ck = SGAKAXor(out, OPcV)

	for i := 0; i < 16; i++ {
		eData[(i+8)%16] = tmp[i] ^ OPcV[i]
	}
	eData[15] ^= 4

	out, err = SGAKAEncrypt(K, eData)
	if err != nil {
		return
	}
	ik = SGAKAXor(out, OPcV)

	return res, ck, ik, ak, nil
}

// SGAKAHandleChallenge processes the authentication challenge from the server
func SGAKAHandleChallenge(username string, key, op, opc, amf []byte, challengeParams map[string]string) (string, error) {
	var uri, nonce, realm, method, qop string

	nonce = challengeParams["nonce"]
	realm = challengeParams["realm"]
	method = challengeParams["method"]
	qop = challengeParams["qop"]
	if _, ok := challengeParams["uri"]; ok {
		uri = challengeParams["uri"]
	} else {
		uri = fmt.Sprintf("sip:%s", realm)
	}
	if nonce == "" || realm == "" {
		return "", errors.New("missing required parameters in challenge")
	}

	rand, autn, err := SGAKAParseNonce(nonce)
	if err != nil {
		return "", fmt.Errorf("failed to parse nonce: %w", err)
	}

	// Generate RES
	sqnxorak := autn[0:6]
	amfin := autn[6:8]
	mac := autn[8:16]

	if SGAKACompareBytes(amf, amfin) != 0 {
		return "", fmt.Errorf("failed to match amf")
	}

	res, ck, ik, ak, err := SGAKAComputeF2345(key, op, opc, rand)
	if err != nil {
		return "", fmt.Errorf("failed to generate res: %w", err)
	}
	sqn := SGAKAXor(sqnxorak, ak)

	xmac, err := SGAKAComputeF1(key, op, opc, rand, sqn, amfin)
	if err != nil {
		return "", fmt.Errorf("failed to xmac: %w", err)
	}
	if SGAKACompareBytes(mac, xmac) != 0 {
		return "", fmt.Errorf("failed to match xmac")
	}

	challengeParams["ck"] = fmt.Sprintf("%x", ck)
	challengeParams["ik"] = fmt.Sprintf("%x", ik)

	a1b := make([]byte, 0, len(username)+len(realm)+len(res)+2)
	a1w := bytes.NewBuffer(a1b)
	a1w.WriteString(username)
	a1w.WriteRune(':')
	a1w.WriteString(realm)
	a1w.WriteRune(':')
	a1w.Write(res)

	ha1 := fmt.Sprintf("%x", md5.Sum(a1w.Bytes()))

	a2b := make([]byte, 0, len(method)+len(uri)+1)
	a2w := bytes.NewBuffer(a2b)
	a2w.WriteString(method)
	a2w.WriteRune(':')
	a2w.WriteString(uri)

	ha2 := fmt.Sprintf("%x", md5.Sum(a2w.Bytes()))

	nc := fmt.Sprintf("%08x", 1)
	cnonce := SGCreateClientNonce(8)

	a3b := make([]byte, 0, len(ha1)+len(nonce)+len(nc)+len(cnonce)+len(qop)+len(ha2)+5)
	a3w := bytes.NewBuffer(a3b)
	a3w.WriteString(ha1)
	a3w.WriteRune(':')
	a3w.WriteString(nonce)
	a3w.WriteRune(':')
	a3w.WriteString(nc)
	a3w.WriteRune(':')
	a3w.WriteString(cnonce)
	a3w.WriteRune(':')
	a3w.WriteString(qop)
	a3w.WriteRune(':')
	a3w.WriteString(ha2)
	authres := fmt.Sprintf("%x", md5.Sum(a3w.Bytes()))

	authHeader := fmt.Sprintf(`Digest username="%s",
                 realm="%s",
                 uri="%s",
                 algorithm=%s,
                 nonce="%s",
                 qop=%s,
                 nc=%s,
                 cnonce="%s",
                 response="%s"`,
		username,
		realm,
		uri,
		challengeParams["algorithm"],
		nonce,
		qop,
		nc,
		cnonce,
		authres,
	)

	return authHeader, nil
}

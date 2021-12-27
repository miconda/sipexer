package sgsip

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// return and error code values
const (
	SGSIPRetOK = 0
	// generic errors
	SGSIPRetErr      = -1
	SGSIPRetNotFound = -2

	// first line parse errors
	SGSIPRetErrFLineShort          = -100
	SGSIPRetErrFLineFormat         = -101
	SGSIPRetErrFLineResponseShort  = -102
	SGSIPRetErrFLineResponseFormat = -103
	SGSIPRetErrFLineResponseCode   = -104
	SGSIPRetErrFLineRequestFormat  = -120
)

const (
	ProtoNONE = iota
	ProtoUDP
	ProtoTCP
	ProtoTLS
	ProtoSCTP
	ProtoWS
	ProtoWSS
)

const (
	AFNONE = iota
	AFIPv4
	AFIPv6
	AFHost
)

const (
	SchemaNONE = iota
	SchemaSIP
	SchemaSIPS
	SchemaTEL
)

const (
	ParamValNone = iota
	ParamValBare
	ParamValQuoted
)

const (
	FLineNone = iota
	FLineRequest
	FLineResponse
)

type SGSIPSocketAddress struct {
	val     string
	proto   string
	addr    string
	port    string
	portno  int
	atype   int
	protoid int
}

type SGSIPURI struct {
	val      string
	schema   string
	schemaid int
	user     string
	addr     string
	port     string
	portno   int
	params   string
	uparams  string
	proto    string
	protoid  int
	atype    int
}

type SGSIPParam struct {
	name  string
	value string
	pmode int
}

type SGSIPFirstLine struct {
	mtype    int
	proto    string
	method   string
	methodid int
	uri      string
	code     int    // status code number
	codeval  string // status code string
	reason   string
}

// Quick detection of ip/address type
func SGAddrType(addr string) int {
	if net.ParseIP(addr) == nil {
		return AFHost
	}
	for i := 0; i < len(addr); i++ {
		switch addr[i] {
		case '.':
			return AFIPv4
		case ':':
			return AFIPv6
		}
	}
	return AFNONE
}

// SGSIPSetProto --
func SGSIPSetProto(protostr string, protoval *string, protoid *int) int {
	switch protostr {
	case "udp", "UDP":
		*protoid = ProtoUDP
		*protoval = "udp"
		return SGSIPRetOK
	case "tcp", "TCP":
		*protoid = ProtoTCP
		*protoval = "tcp"
		return SGSIPRetOK
	case "tls", "TLS":
		*protoid = ProtoTLS
		*protoval = "tls"
		return SGSIPRetOK
	case "sctp", "SCTP":
		*protoid = ProtoSCTP
		*protoval = "sctp"
		return SGSIPRetOK
	case "ws", "WS":
		*protoid = ProtoWS
		*protoval = "ws"
		return SGSIPRetOK
	case "wss", "WSS":
		*protoid = ProtoWSS
		*protoval = "wss"
		return SGSIPRetOK
	}
	return SGSIPRetErr
}

// SGSIPSetSchema --
func SGSIPSetSchema(schemastr string, schemaval *string, schemaid *int) int {
	switch schemastr {
	case "sip", "SIP":
		*schemaval = "sip"
		*schemaid = SchemaSIP
		return SGSIPRetOK
	case "sips", "SIPS":
		*schemaval = "sips"
		*schemaid = SchemaSIPS
		return SGSIPRetOK
	case "tel", "TEL":
		*schemaval = "tel"
		*schemaid = SchemaTEL
		return SGSIPRetOK
	default:
		return SGSIPRetErr
	}
}

// SGSIPParseSocketAddress --
func SGSIPParseSocketAddress(sockstr string, sockaddr *SGSIPSocketAddress) int {
	if sockstr[0:1] == "[" && sockstr[len(sockstr)-1:] == "]" {
		// assuming only IPv6 address -- fill with defaults
		sockaddr.atype = SGAddrType(sockaddr.addr)
		if sockaddr.atype != AFIPv6 {
			return SGSIPRetErr
		}
		sockaddr.val = sockstr
		sockaddr.proto = "udp"
		sockaddr.protoid = ProtoUDP
		sockaddr.addr = sockstr
		sockaddr.port = "5060"
		sockaddr.portno = 5060
		return SGSIPRetOK
	}
	strArray := strings.SplitN(sockstr, ":", 2)
	if len(strArray) == 1 {
		// only host address -- fill with defaults
		sockaddr.val = sockstr
		sockaddr.proto = "udp"
		sockaddr.protoid = ProtoUDP
		sockaddr.addr = sockstr
		sockaddr.port = "5060"
		sockaddr.portno = 5060
		sockaddr.atype = SGAddrType(sockaddr.addr)
		return SGSIPRetOK
	}
	strProto := strArray[0]
	strAddrPort := strArray[1]

	ret := SGSIPSetProto(strProto, &sockaddr.proto, &sockaddr.protoid)
	if ret != SGSIPRetOK {
		// first token is not proto - assume addr:port
		sockaddr.proto = "udp"
		sockaddr.protoid = ProtoUDP
		strAddrPort = sockstr
		strProto = ""
	}
	if strAddrPort[0:1] == "[" {
		strArray = strings.SplitN(strAddrPort, "]", 2)
		if strProto == "" && strArray[1][0:1] != ":" {
			// no port and only IPv6 tested before
			return SGSIPRetErr
		}
		sockaddr.port = strArray[1][1:]
		i, err := strconv.Atoi(sockaddr.port)
		if err != nil {
			return SGSIPRetErr
		}
		sockaddr.portno = i
		sockaddr.addr = strArray[0] + "]"
		sockaddr.atype = SGAddrType(sockaddr.addr)
		if sockaddr.atype != AFIPv6 {
			return SGSIPRetErr
		}
	} else {
		strArray = strings.SplitN(strAddrPort, ":", 2)
		sockaddr.port = strArray[1]
		i, err := strconv.Atoi(sockaddr.port)
		if err != nil {
			return SGSIPRetErr
		}
		sockaddr.portno = i
		sockaddr.addr = strArray[0]
		sockaddr.atype = SGAddrType(sockaddr.addr)
	}
	sockaddr.val = sockstr
	return SGSIPRetOK
}

// SGSIPParseURI --
func SGSIPParseURI(uristr string, uri *SGSIPURI) int {
	strArray := strings.SplitN(uristr, ":", 2)

	if len(strArray) < 2 {
		return SGSIPRetErr
	}
	ret := SGSIPSetSchema(strArray[0], &uri.schema, &uri.schemaid)
	if ret != SGSIPRetOK {
		return ret
	}
	atPos := strings.Index(strArray[1], "@")
	colPos := strings.Index(strArray[1], ":")
	scPos := strings.Index(strArray[1], ";")
	if atPos == 0 {
		// empty user part
		return SGSIPRetErr
	}
	if atPos < 0 && colPos < 0 && scPos < 0 {
		// no user, no port, no parameters
		uri.addr = strArray[1]
		uri.proto = "udp"
		uri.protoid = ProtoUDP
		uri.port = "5060"
		uri.portno = 5060
		uri.atype = SGAddrType(uri.addr)
		uri.val = uristr
		return SGSIPRetOK
	}
	pHostPP := ""
	if atPos > 0 {
		pUser := strArray[1][0:atPos]
		pHostPP = strArray[1][atPos+1:]
		uScPos := strings.Index(pUser, ";")
		if uScPos == 0 {
			// empty user part
			return SGSIPRetErr
		}
		if uScPos < 0 {
			uri.user = pUser
		} else {
			uri.user = pUser[0 : uScPos+1]
			uri.uparams = pUser[uScPos+1:]
		}
	} else {
		pHostPP = strArray[1]
	}
	if colPos < 0 && scPos < 0 {
		// no port, no params
		uri.addr = pHostPP
		uri.proto = "udp"
		uri.protoid = ProtoUDP
		uri.port = "5060"
		uri.portno = 5060
		uri.atype = SGAddrType(uri.addr)
		uri.val = uristr
		return SGSIPRetOK
	}
	pPortParams := ""
	if pHostPP[0:1] == "[" {
		if pHostPP[len(pHostPP)-1:] == "]" {
			// only IPv6 address
			uri.addr = pHostPP
			uri.proto = "udp"
			uri.protoid = ProtoUDP
			uri.port = "5060"
			uri.portno = 5060
			uri.atype = SGAddrType(uri.addr)
			if uri.atype != AFIPv6 {
				return SGSIPRetErr
			}
			uri.val = uristr
			return SGSIPRetOK
		}
		strArray = strings.SplitN(pHostPP, "]", 2)
		uri.addr = strArray[0] + "]"
		uri.atype = SGAddrType(uri.addr[1 : len(uri.addr)-1])
		if uri.atype != AFIPv6 {
			return SGSIPRetErr
		}
		pPortParams = strArray[1]
	} else {
		scPos = strings.IndexAny(pHostPP, ":;")
		uri.addr = pHostPP[0:scPos]
		uri.atype = SGAddrType(uri.addr)
		pPortParams = pHostPP[scPos:]
	}
	fmt.Printf("--- pPortParams: %v\n", pPortParams)
	pParams := ""
	if pPortParams[0:1] == ":" {
		// port
		pPort := ""
		scPos = strings.Index(pPortParams, ";")
		if scPos < 0 {
			pPort = pPortParams[1:]
		} else {
			pPort = pPortParams[1:scPos]
		}
		i, err := strconv.Atoi(pPort)
		if err != nil || i <= 0 {
			return SGSIPRetErr
		}
		uri.port = pPort
		uri.portno = i
		if scPos < 0 {
			uri.proto = "udp"
			uri.protoid = ProtoUDP
			uri.val = uristr
			return SGSIPRetOK
		}
		pParams = pPortParams[scPos:]
	} else if pPortParams[0:1] == ";" {
		pParams = pPortParams
	} else {
		return SGSIPRetErr
	}
	uri.proto = "udp"
	uri.protoid = ProtoUDP
	if len(pParams) > 0 {
		uri.params = pParams[1:]
		strArray = strings.Split(pParams, ";transport=")
		if len(strArray) == 1 {
			uri.val = uristr
			return SGSIPRetOK
		}
		scPos = strings.Index(strArray[1], ";")
		pProto := ""
		if scPos < 0 {
			pProto = strArray[1]
		} else {
			pProto = strArray[1][0:scPos]
		}
		ret := SGSIPSetProto(pProto, &uri.proto, &uri.protoid)
		if ret != SGSIPRetOK {
			return SGSIPRetErr
		}
	}
	uri.val = uristr
	return SGSIPRetOK
}

// SGSIPParamsGet --
func SGSIPParamsGet(paramStr string, paramName string, vmode int, paramVal *SGSIPParam) int {
	if len(paramStr) < len(paramName) {
		return SGSIPRetNotFound
	}
	pStr := paramStr
	if pStr[0:1] != ";" {
		pStr = ";" + pStr
	}
	if pStr[len(pStr)-1:] != ";" {
		pStr = pStr + ";"
	}

	if strings.Index(pStr, ";"+paramName+";") >= 0 {
		// parameter without value
		paramVal.name = paramName
		paramVal.value = ""
		paramVal.pmode = ParamValBare
		return SGSIPRetOK
	}

	strArray := strings.Split(pStr, ";"+paramName+"=")
	if len(strArray) == 1 {
		return SGSIPRetNotFound
	}
	scPos := -1
	qVal := 0
	if strArray[1][0:1] == "\"" {
		if vmode == 0 {
			return SGSIPRetErr
		}
		scPos = strings.Index(strArray[1], "\";")
		paramVal.pmode = ParamValQuoted
		qVal = 1
	} else {
		paramVal.pmode = ParamValBare
		scPos = strings.Index(strArray[1], ";")
	}
	if scPos < 0 {
		paramVal.value = strArray[1]
	} else {
		paramVal.value = strArray[1][0 : scPos+qVal]
	}
	paramVal.name = paramName
	return SGSIPRetOK
}

// SGSIPParseFirstLine --
func SGSIPParseFirstLine(inputStr string, flineVal *SGSIPFirstLine) int {
	strArray := strings.SplitN(inputStr, "\n", 2)
	strFLine := strings.Trim(strArray[0], " \t\r")
	if len(strFLine) < 8 {
		return SGSIPRetErrFLineShort
	}
	if strFLine[0:8] == "SIP/2.0 " {
		flineVal.mtype = FLineResponse
	} else if strFLine[len(strFLine)-8:] == " SIP/2.0" {
		flineVal.mtype = FLineRequest
	} else {
		return SGSIPRetErrFLineFormat
	}
	if flineVal.mtype == FLineResponse {
		strCR := strFLine[8:]
		if len(strCR) < 5 {
			return SGSIPRetErrFLineResponseShort
		}
		strArray = strings.SplitN(strCR, " ", 2)
		if len(strArray) < 2 || len(strArray[0]) != 3 {
			return SGSIPRetErrFLineResponseFormat
		}
		i, err := strconv.Atoi(strArray[0])
		if err != nil || i < 100 || i > 999 {
			return SGSIPRetErrFLineResponseCode
		}
		flineVal.code = i
		flineVal.codeval = strArray[0]
		flineVal.reason = strings.Trim(strArray[1], " \t\r")
		return SGSIPRetOK
	}
	strMU := strFLine[0 : len(strFLine)-8]
	strArray = strings.SplitN(strMU, " ", 2)
	if len(strArray) < 2 || len(strArray[0]) < 3 || len(strArray[1]) < 5 {
		return SGSIPRetErrFLineRequestFormat
	}
	flineVal.method = strings.Trim(strArray[0], " \t\r")
	flineVal.uri = strings.Trim(strArray[1], " \t\r")
	return SGSIPRetOK
}

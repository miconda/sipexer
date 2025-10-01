// SIPExer Generic SIP Parsing Library
package sgsip

import (
	"net"
	"strconv"
	"strings"

	"github.com/google/uuid"
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
	SGSIPRetErrFLineRequestFormat  = -102
	SGSIPRetErrFLineResponseShort  = -103
	SGSIPRetErrFLineResponseFormat = -104
	SGSIPRetErrFLineResponseCode   = -105

	// sip params parse errors
	SGSIPRetErrParamFormat   = -140
	SGSIPRetErrParamNotFound = -141

	// socket address error
	SGSIPRetErrSocketAddressPort    = -200
	SGSIPRetErrSocketAddressPortVal = -201
	SGSIPRetErrSocketAddressAFIPv6  = -202

	// uri errors
	SGSIPRetErrURI       = -220
	SGSIPRetErrURIUser   = -221
	SGSIPRetErrURIAFIPv6 = -222
	SGSIPRetErrURIPort   = -223
	SGSIPRetErrURIFormat = -224
	SGSIPRetErrURIProto  = -225

	// header errors
	SGSIPRetErrHeaderLength = -240
	SGSIPRetErrHeaderEmpty  = -241
	SGSIPRetErrHeaderFormat = -242
	SGSIPRetErrHeaderName   = -243
	SGSIPRetErrHeaderEoL    = -244

	// body errors
	SGSIPRetErrBody = -260

	// cseq errors
	SGSIPRetErrCSeqBody   = -280
	SGSIPRetErrCSeqNumber = -281

	// sip message errors
	SGSIPRetErrMessageNotSet = -300
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
	AFNONE = 0
	AFIPv4 = 4
	AFIPv6 = 6
	AFHost = 8
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

const (
	SIPMethodNONE = iota
	SIPMethodINVITE
	SIPMethodACK
	SIPMethodBYE
	SIPMethodCANCEL
	SIPMethodREGISTER
	SIPMethodMESSAGE
	SIPMethodOPTIONS
	SIPMethodINFO
	SIPMethodUPDATE
	SIPMethodSUBSCRIBE
	SIPMethodNOTIFY
	SIPMethodPUBLISH
	SIPMethodPRACK
	SIPMethodOTHER
)

const (
	HeaderTypeNone = iota
	HeaderTypeCallID
	HeaderTypeCSeq
	HeaderTypeFrom
	HeaderTypeTo
	HeaderTypeVia
	HeaderTypeContact
	HeaderTypeSubject
	HeaderTypeContentLength
	HeaderTypeContentType
	HeaderTypeContentEncoding
	HeaderTypeAcceptContact
	HeaderTypeReferTo
	HeaderTypeReferredBy
	HeaderTypeEvent
	HeaderTypeAllowEvents
	HeaderTypeSupported
	HeaderTypeRecordRoute
	HeaderTypeRoute
	HeaderTypeExpires
	HeaderTypeUserAgent
	HeaderTypeAuthorization
	HeaderTypeProxyAuthorization
	HeaderTypeOther
)

type SGSIPSocketAddress struct {
	Val     string
	Proto   string
	Addr    string
	Port    string
	PortNo  int
	AType   int
	ProtoId int
}

type SGSIPURI struct {
	Val      string
	Schema   string
	SchemaId int
	User     string
	Addr     string
	Port     string
	PortNo   int
	Params   string
	UParams  string
	Proto    string
	ProtoId  int
	AType    int
}

type SGSIPParam struct {
	Name  string
	Value string
	PMode int
}

type SGSIPFirstLine struct {
	Val      string
	MType    int
	Proto    string
	Method   string
	MethodId int
	URI      string
	Code     int    // status code number
	CodeVal  string // status code string
	Reason   string
}

type SGSIPHeader struct {
	Name  string
	Body  string
	HType int
}

type SGSIPCSeq struct {
	Number   int
	Method   string
	MethodId int
}

type SGSIPBody struct {
	Content     string
	ContentLen  int
	ContentType string
}

// message flags
const (
	SGSIPMFlagNone      = 0
	SGSIPMFlagLateOffer = 1
)

type SGSIPMessage struct {
	Data    string
	FLine   SGSIPFirstLine
	RURI    SGSIPURI
	Headers []SGSIPHeader
	CSeq    SGSIPCSeq
	Body    SGSIPBody
	MFlags  int
}

var viaBranchCookie string = "z9hG4bKSG."

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

// Quick detection of ip/address type also with IPv6 square brackets
func SGAddrTypeEx(addr string) int {
	if addr[0:1] == "[" {
		// assuming only IPv6 address
		if addr[len(addr)-1:] != "]" {
			return AFNONE
		}
		if SGAddrType(addr[1:len(addr)-1]) != AFIPv6 {
			return AFNONE
		}
		return AFIPv6
	} else {
		return SGAddrType(addr)
	}
}

// SGSIPSetProto --
func SGSIPSetProto(protostr string, protoval *string, protoid *int) int {
	switch strings.ToLower(protostr) {
	case "udp":
		*protoid = ProtoUDP
		*protoval = "udp"
		return SGSIPRetOK
	case "tcp":
		*protoid = ProtoTCP
		*protoval = "tcp"
		return SGSIPRetOK
	case "tls":
		*protoid = ProtoTLS
		*protoval = "tls"
		return SGSIPRetOK
	case "sctp":
		*protoid = ProtoSCTP
		*protoval = "sctp"
		return SGSIPRetOK
	case "ws":
		*protoid = ProtoWS
		*protoval = "ws"
		return SGSIPRetOK
	case "wss":
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

// SGSIPSetMethodId --
func SGSIPSetMethodId(method string, methodid *int) {
	switch strings.ToUpper(method) {
	case "INVITE":
		*methodid = SIPMethodINVITE
		return
	case "ACK":
		*methodid = SIPMethodACK
		return
	case "BYE":
		*methodid = SIPMethodBYE
		return
	case "CANCEL":
		*methodid = SIPMethodCANCEL
		return
	case "REGISTER":
		*methodid = SIPMethodREGISTER
		return
	case "MESSAGE":
		*methodid = SIPMethodMESSAGE
		return
	case "OPTIONS":
		*methodid = SIPMethodOPTIONS
		return
	case "INFO":
		*methodid = SIPMethodINFO
		return
	case "UPDATE":
		*methodid = SIPMethodUPDATE
		return
	case "SUBSCRIBE":
		*methodid = SIPMethodSUBSCRIBE
		return
	case "NOTIFY":
		*methodid = SIPMethodNOTIFY
		return
	case "PUBLISH":
		*methodid = SIPMethodPUBLISH
		return
	case "PRACK":
		*methodid = SIPMethodPRACK
		return
	default:
		*methodid = SIPMethodOTHER
		return
	}
}

// SGSIPParseSocketAddress --
func SGSIPParseSocketAddress(sockstr string, sockaddr *SGSIPSocketAddress) int {
	if sockstr[0:1] == "[" && sockstr[len(sockstr)-1:] == "]" {
		sockaddr.Addr = sockstr
		// assuming only IPv6 address -- fill with defaults
		sockaddr.AType = SGAddrTypeEx(sockaddr.Addr)
		if sockaddr.AType != AFIPv6 {
			return SGSIPRetErrSocketAddressAFIPv6
		}
		sockaddr.Val = sockstr
		sockaddr.Proto = "udp"
		sockaddr.ProtoId = ProtoUDP
		sockaddr.Port = "5060"
		sockaddr.PortNo = 5060
		return SGSIPRetOK
	}
	strArray := strings.SplitN(sockstr, ":", 2)
	if len(strArray) == 1 {
		// only host address -- fill with defaults
		sockaddr.Val = sockstr
		sockaddr.Proto = "udp"
		sockaddr.ProtoId = ProtoUDP
		sockaddr.Addr = sockstr
		sockaddr.Port = "5060"
		sockaddr.PortNo = 5060
		sockaddr.AType = SGAddrType(sockaddr.Addr)
		return SGSIPRetOK
	}
	strProto := strArray[0]
	strAddrPort := strArray[1]

	ret := SGSIPSetProto(strProto, &sockaddr.Proto, &sockaddr.ProtoId)
	if ret != SGSIPRetOK {
		// first token is not proto - assume addr:port
		sockaddr.Proto = "udp"
		sockaddr.ProtoId = ProtoUDP
		strAddrPort = sockstr
		strProto = ""
	}
	if strAddrPort[0:1] == "[" {
		strArray = strings.SplitN(strAddrPort, "]", 2)
		if strProto == "" && strArray[1][0:1] != ":" {
			// no port and only IPv6 tested before
			return SGSIPRetErrSocketAddressPort
		}
		sockaddr.Port = strArray[1][1:]
		i, err := strconv.Atoi(sockaddr.Port)
		if err != nil {
			return SGSIPRetErrSocketAddressPortVal
		}
		sockaddr.PortNo = i
		sockaddr.Addr = strArray[0] + "]"
		sockaddr.AType = SGAddrTypeEx(sockaddr.Addr)
		if sockaddr.AType != AFIPv6 {
			return SGSIPRetErrSocketAddressAFIPv6
		}
	} else {
		strArray = strings.SplitN(strAddrPort, ":", 2)
		if len(strArray) > 1 {
			sockaddr.Port = strArray[1]
			i, err := strconv.Atoi(sockaddr.Port)
			if err != nil {
				return SGSIPRetErrSocketAddressPortVal
			}
			sockaddr.PortNo = i
		} else {
			sockaddr.Port = "5060"
			sockaddr.PortNo = 5060
		}
		sockaddr.Addr = strArray[0]
		sockaddr.AType = SGAddrType(sockaddr.Addr)
	}
	sockaddr.Val = sockstr
	return SGSIPRetOK
}

// SGSIPParseURI --
func SGSIPParseURI(uristr string, uri *SGSIPURI) int {
	strArray := strings.SplitN(uristr, ":", 2)

	if len(strArray) < 2 {
		return SGSIPRetErrURI
	}
	ret := SGSIPSetSchema(strArray[0], &uri.Schema, &uri.SchemaId)
	if ret != SGSIPRetOK {
		return ret
	}
	atPos := strings.Index(strArray[1], "@")
	colPos := strings.Index(strArray[1], ":")
	scPos := strings.Index(strArray[1], ";")
	if atPos == 0 {
		// empty user part
		return SGSIPRetErrURIUser
	}
	if atPos < 0 && colPos < 0 && scPos < 0 {
		// no user, no port, no parameters
		uri.Addr = strArray[1]
		uri.Proto = "udp"
		uri.ProtoId = ProtoUDP
		uri.Port = "5060"
		uri.PortNo = 5060
		uri.AType = SGAddrType(uri.Addr)
		uri.Val = uristr
		return SGSIPRetOK
	}
	pHostPP := ""
	if atPos > 0 {
		pUser := strArray[1][0:atPos]
		pHostPP = strArray[1][atPos+1:]
		uScPos := strings.Index(pUser, ";")
		if uScPos == 0 {
			// empty user part
			return SGSIPRetErrURIUser
		}
		if uScPos < 0 {
			uri.User = pUser
		} else {
			uri.User = pUser[0 : uScPos+1]
			uri.UParams = pUser[uScPos+1:]
		}
	} else {
		pHostPP = strArray[1]
	}
	if colPos < 0 && scPos < 0 {
		// no port, no params
		uri.Addr = pHostPP
		uri.Proto = "udp"
		uri.ProtoId = ProtoUDP
		uri.Port = "5060"
		uri.PortNo = 5060
		uri.AType = SGAddrType(uri.Addr)
		uri.Val = uristr
		return SGSIPRetOK
	}
	pPortParams := ""
	if pHostPP[0:1] == "[" {
		if pHostPP[len(pHostPP)-1:] == "]" {
			// only IPv6 address
			uri.Addr = pHostPP
			uri.Proto = "udp"
			uri.ProtoId = ProtoUDP
			uri.Port = "5060"
			uri.PortNo = 5060
			uri.AType = SGAddrTypeEx(uri.Addr)
			if uri.AType != AFIPv6 {
				return SGSIPRetErrURIAFIPv6
			}
			uri.Val = uristr
			return SGSIPRetOK
		}
		strArray = strings.SplitN(pHostPP, "]", 2)
		uri.Addr = strArray[0] + "]"
		uri.AType = SGAddrTypeEx(uri.Addr)
		if uri.AType != AFIPv6 {
			return SGSIPRetErrURIAFIPv6
		}
		pPortParams = strArray[1]
	} else {
		scPos = strings.IndexAny(pHostPP, ":;")
		uri.Addr = pHostPP[0:scPos]
		uri.AType = SGAddrType(uri.Addr)
		pPortParams = pHostPP[scPos:]
	}
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
			return SGSIPRetErrURIPort
		}
		uri.Port = pPort
		uri.PortNo = i
		if scPos < 0 {
			uri.Proto = "udp"
			uri.ProtoId = ProtoUDP
			uri.Val = uristr
			return SGSIPRetOK
		}
		pParams = pPortParams[scPos:]
	} else if pPortParams[0:1] == ";" {
		pParams = pPortParams
	} else {
		return SGSIPRetErrURIFormat
	}
	uri.Proto = "udp"
	uri.ProtoId = ProtoUDP
	if len(pParams) > 0 {
		uri.Params = pParams[1:]
		strArray = strings.Split(pParams, ";transport=")
		if len(strArray) == 1 {
			uri.Val = uristr
			return SGSIPRetOK
		}
		scPos = strings.Index(strArray[1], ";")
		pProto := ""
		if scPos < 0 {
			pProto = strArray[1]
		} else {
			pProto = strArray[1][0:scPos]
		}
		ret := SGSIPSetProto(pProto, &uri.Proto, &uri.ProtoId)
		if ret != SGSIPRetOK {
			return SGSIPRetErrURIProto
		}
	}
	uri.Val = uristr
	return SGSIPRetOK
}

// SGSIPURIToSocketAddress --
func SGSIPURIToSocketAddress(uri *SGSIPURI, sockaddr *SGSIPSocketAddress) int {
	if len(uri.Proto) > 0 {
		sockaddr.Proto = uri.Proto
		sockaddr.ProtoId = uri.ProtoId
	} else {
		sockaddr.Proto = "udp"
		sockaddr.ProtoId = ProtoUDP
	}
	if len(uri.Addr) > 0 {
		sockaddr.Addr = uri.Addr
	} else {
		sockaddr.Addr = "127.0.0.1"
	}
	sockaddr.AType = SGAddrTypeEx(sockaddr.Addr)

	if len(uri.Port) > 0 {
		sockaddr.Port = uri.Port
		sockaddr.PortNo = uri.PortNo
	} else {
		sockaddr.Port = "5060"
		sockaddr.PortNo = 5060
	}
	sockaddr.Val = sockaddr.Proto + ":" + sockaddr.Addr + ":" + sockaddr.Port
	return SGSIPRetOK
}

// SGSocketAddressToSIPURI --
func SGSocketAddressToSIPURI(sockaddr *SGSIPSocketAddress, user string, tmode int, uri *SGSIPURI) int {
	if len(sockaddr.Proto) > 0 {
		uri.Proto = sockaddr.Proto
		uri.ProtoId = sockaddr.ProtoId
	} else {
		uri.Proto = "udp"
		uri.ProtoId = ProtoUDP
	}
	upart := ""
	if len(user) > 0 {
		uri.User = user
		upart = user + "@"
	}
	if len(sockaddr.Addr) > 0 {
		uri.Addr = sockaddr.Addr
	} else {
		uri.Addr = "127.0.0.1"
	}
	uri.AType = SGAddrTypeEx(uri.Addr)

	if len(sockaddr.Port) > 0 {
		uri.Port = sockaddr.Port
		uri.PortNo = sockaddr.PortNo
	} else {
		uri.Port = "5060"
		uri.PortNo = 5060
	}
	uri.Schema = "sip"
	uri.SchemaId = SchemaSIP

	if tmode == 0 && uri.ProtoId == ProtoUDP {
		uri.Val = uri.Schema + ":" + upart + sockaddr.Addr + ":" + sockaddr.Port
	} else {
		uri.Val = uri.Schema + ":" + upart + sockaddr.Addr + ":" + sockaddr.Port + ";transport=" + sockaddr.Proto
	}

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

	if strings.Contains(pStr, ";"+paramName+";") {
		// parameter without value
		paramVal.Name = paramName
		paramVal.Value = ""
		paramVal.PMode = ParamValBare
		return SGSIPRetOK
	}

	strArray := strings.Split(pStr, ";"+paramName+"=")
	if len(strArray) == 1 {
		return SGSIPRetErrParamNotFound
	}
	scPos := -1
	qVal := 0
	if strArray[1][0:1] == "\"" {
		if vmode == 0 {
			return SGSIPRetErrParamFormat
		}
		scPos = strings.Index(strArray[1], "\";")
		paramVal.PMode = ParamValQuoted
		qVal = 1
	} else {
		paramVal.PMode = ParamValBare
		scPos = strings.Index(strArray[1], ";")
	}
	if scPos < 0 {
		paramVal.Value = strArray[1]
	} else {
		paramVal.Value = strArray[1][0 : scPos+qVal]
	}
	paramVal.Name = paramName
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
		flineVal.MType = FLineResponse
	} else if strFLine[len(strFLine)-8:] == " SIP/2.0" {
		flineVal.MType = FLineRequest
	} else {
		return SGSIPRetErrFLineFormat
	}
	flineVal.Val = strFLine
	flineVal.Proto = "SIP/2.0"
	if flineVal.MType == FLineResponse {
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
		flineVal.Code = i
		flineVal.CodeVal = strArray[0]
		flineVal.Reason = strings.Trim(strArray[1], " \t\r")
		return SGSIPRetOK
	}
	strMU := strFLine[0 : len(strFLine)-8]
	strArray = strings.SplitN(strMU, " ", 2)
	if len(strArray) < 2 || len(strArray[0]) < 3 || len(strArray[1]) < 5 {
		return SGSIPRetErrFLineRequestFormat
	}
	flineVal.Method = strings.Trim(strArray[0], " \t\r")
	SGSIPSetMethodId(flineVal.Method, &flineVal.MethodId)
	flineVal.URI = strings.Trim(strArray[1], " \t\r")
	return SGSIPRetOK
}

// SGSIPValidHeaderName --
func SGSIPHeaderValidName(name string) bool {
	for i, r := range name {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			if i == 0 {
				return false
			}
			if (r < '0' || r > '9') && (r != '-') {
				return false
			}
		}
	}
	return true
}

// SGSIPHeaderParseDigestAuthBody - parse www/proxy-authenticate header body.
// Return a map of parameters or nil if the header is not Digest auth header.
func SGSIPHeaderParseDigestAuthBody(hbody string) map[string]string {
	s := strings.SplitN(strings.Trim(hbody, " "), " ", 2)
	if len(s) != 2 || s[0] != "Digest" {
		return nil
	}

	params := map[string]string{}
	for _, kv := range strings.Split(s[1], ",") {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		params[strings.ToLower(strings.Trim(parts[0], "\" "))] = strings.Trim(parts[1], "\" ")
	}
	return params
}

// SGSIPParseHeader --
func SGSIPParseHeaders(inputStr string, pMode int, headersList *[]SGSIPHeader) int {
	var strArray []string
	var strHeaders string
	if pMode == 0 {
		strArray = strings.SplitN(inputStr, "\n", 2)
		if len(strArray) < 2 {
			return SGSIPRetErrHeaderLength
		}
		strHeaders = strArray[1]
	} else {
		strHeaders = strings.TrimLeft(inputStr, " \t\r\n")
	}
	if len(strHeaders) == 0 || strHeaders[0:1] == "\r" || strHeaders[0:1] == "\n" {
		// empty or first char is an EoL
		return SGSIPRetErrHeaderEmpty
	}
	for {
		var hdrItem SGSIPHeader = SGSIPHeader{}
		// split name: body
		strArray = strings.SplitN(strHeaders, ":", 2)
		if len(strArray) < 2 || len(strArray[0]) == 0 || len(strArray[1]) == 0 {
			return SGSIPRetErrHeaderFormat
		}
		if !SGSIPHeaderValidName(strArray[0]) {
			return SGSIPRetErrHeaderName
		}
		hdrItem.Name = strings.TrimRight(strArray[0], " \t")
		hdrItem.HType = SGSIPHeaderGetType(hdrItem.Name)
		hdrItem.Body = ""
		for {
			strArray = strings.SplitN(strArray[1], "\n", 2)
			if len(strArray) < 2 {
				return SGSIPRetErrHeaderEoL
			}
			hdrItem.Body += strArray[0]
			if len(strArray[1]) == 0 {
				break
			}
			// check if body spans over next line
			if strArray[1][0:1] != " " && strArray[1][0:1] != "\t" {
				break
			}
		}
		hdrItem.Body = strings.Trim(hdrItem.Body, " \t\r")
		*headersList = append(*headersList, hdrItem)
		strHeaders = strArray[1]
		if len(strHeaders) == 0 || strHeaders[0:1] == "\r" || strHeaders[0:1] == "\n" {
			// EoH
			break
		}
	}
	return SGSIPRetOK
}

// SGSIPHeaderGetType --
func SGSIPHeaderGetType(name string) int {
	switch strings.ToLower(name) {
	case "a", "accept-contact":
		return HeaderTypeAcceptContact
	case "b", "referred-by":
		return HeaderTypeReferredBy
	case "c", "content-type":
		return HeaderTypeContentType
	case "e", "content-encoding":
		return HeaderTypeContentEncoding
	case "f", "from":
		return HeaderTypeFrom
	case "i", "call-id":
		return HeaderTypeCallID
	case "k", "supported":
		return HeaderTypeSupported
	case "l", "content-length":
		return HeaderTypeContentLength
	case "m", "contact":
		return HeaderTypeContact
	case "o", "event":
		return HeaderTypeEvent
	case "r", "refer-to":
		return HeaderTypeReferTo
	case "s", "subject":
		return HeaderTypeSubject
	case "t", "to":
		return HeaderTypeTo
	case "u", "allow-events":
		return HeaderTypeAllowEvents
	case "v", "via":
		return HeaderTypeVia
	case "cseq":
		return HeaderTypeCSeq
	case "record-route":
		return HeaderTypeRecordRoute
	case "route":
		return HeaderTypeRoute
	case "expires":
		return HeaderTypeExpires
	case "user-agent":
		return HeaderTypeUserAgent
	case "authorization":
		return HeaderTypeAuthorization
	case "proxy-authorization":
		return HeaderTypeProxyAuthorization
	}
	return HeaderTypeOther
}

// SGSIPParseBody --
func SGSIPParseBody(inputStr string, bodyVal *SGSIPBody) int {
	strArray := strings.SplitN(inputStr, "\r\n\r\n", 2)
	if len(strArray) < 2 {
		strArray := strings.SplitN(inputStr, "\n\n", 2)
		if len(strArray) < 2 {
			return SGSIPRetErrBody
		}
	}
	bodyVal.Content = strArray[1]
	bodyVal.ContentLen = len(strArray[1])
	return SGSIPRetOK
}

// SGSIPMessageHeaderSet --
func SGSIPMessageHeaderSet(msgVal *SGSIPMessage, hname string, hbody string) int {
	htype := SGSIPHeaderGetType(hname)
	for i, hdr := range msgVal.Headers {
		if (htype != HeaderTypeOther && htype == hdr.HType) || (hdr.Name == hname) {
			msgVal.Headers[i].Body = strings.Trim(hbody, " \t\r")
			return SGSIPRetOK
		}
	}
	var hdrItem SGSIPHeader = SGSIPHeader{}
	hdrItem.Name = strings.Trim(hname, " \t\r")
	hdrItem.HType = SGSIPHeaderGetType(hdrItem.Name)
	hdrItem.Body = strings.Trim(hbody, " \t\r")
	msgVal.Headers = append(msgVal.Headers, hdrItem)

	return SGSIPRetOK
}

// SGSIPMessageHeaderGet --
func SGSIPMessageHeaderGet(msgVal *SGSIPMessage, hname string, hbody *string) int {
	htype := SGSIPHeaderGetType(hname)
	for i, hdr := range msgVal.Headers {
		if (htype != HeaderTypeOther && htype == hdr.HType) || (hdr.Name == hname) {
			*hbody = msgVal.Headers[i].Body
			return SGSIPRetOK
		}
	}

	return SGSIPRetNotFound
}

// SGSIPMessageGetContactURI --
func SGSIPMessageGetContactURI(msgVal *SGSIPMessage, cturi *string) int {
	htype := SGSIPHeaderGetType("Contact")
	for i, hdr := range msgVal.Headers {
		if htype != HeaderTypeOther && htype == hdr.HType {
			hbody := msgVal.Headers[i].Body
			p1 := strings.Index(hbody, "<")
			p2 := strings.Index(hbody, ">")
			if p1 < 0 || p2 < 0 {
				// no angle brackets
				p1 = strings.Index(hbody, ";")
				if p1 > 0 {
					*cturi = hbody[0:p1]
				} else {
					*cturi = hbody
				}
			} else {
				if p2 < p1 {
					return SGSIPRetErr
				}
				*cturi = hbody[p1+1 : p2]
			}
			return SGSIPRetOK
		}
	}

	return SGSIPRetNotFound
}

// SGSIPMessageViaUpdate --
func SGSIPMessageViaUpdate(msgObj *SGSIPMessage) int {
	if len(msgObj.FLine.Val) == 0 || len(msgObj.Headers) == 0 {
		return SGSIPRetErrMessageNotSet
	}

	for i, h := range msgObj.Headers {
		switch h.HType {
		case HeaderTypeVia:
			sList := strings.SplitN(h.Body, ";branch=", 2)
			if len(sList) == 2 {
				idxSCol := strings.Index(sList[1], ";")
				if idxSCol < 0 {
					msgObj.Headers[i].Body = sList[0] + ";branch=" + viaBranchCookie + uuid.New().String()
				} else {
					msgObj.Headers[i].Body = sList[0] + ";branch=" + viaBranchCookie + uuid.New().String() + sList[1][idxSCol:]
				}
			}
		}
	}
	return SGSIPRetOK
}

// SGSIPMessageCSeqUpdate --
func SGSIPMessageCSeqUpdate(msgVal *SGSIPMessage, ival int) int {
	for i, hdr := range msgVal.Headers {
		if hdr.HType == HeaderTypeCSeq || strings.ToLower(hdr.Name) == "cseq" {
			slist := strings.SplitN(msgVal.Headers[i].Body, " ", 2)
			if len(slist) != 2 {
				return SGSIPRetErrCSeqBody
			}
			csn, err := strconv.Atoi(slist[0])

			if err != nil {
				return SGSIPRetErrCSeqNumber
			}

			msgVal.Headers[i].Body = strconv.Itoa(csn+ival) + " " + slist[1]
			msgVal.CSeq.Number = csn + ival

			return SGSIPRetOK
		}
	}
	return SGSIPRetNotFound
}

// SGSIPMessageCSeqParse --
func SGSIPMessageCSeqParse(msgVal *SGSIPMessage) int {
	var err error
	for i, hdr := range msgVal.Headers {
		if hdr.HType == HeaderTypeCSeq || strings.ToLower(hdr.Name) == "cseq" {
			slist := strings.SplitN(msgVal.Headers[i].Body, " ", 2)
			if len(slist) != 2 {
				return SGSIPRetErrCSeqBody
			}
			msgVal.CSeq.Number, err = strconv.Atoi(slist[0])

			if err != nil {
				msgVal.CSeq.Number = 0
				return SGSIPRetErrCSeqNumber
			}
			msgVal.CSeq.Method = strings.Trim(slist[1], " \t\r")
			SGSIPSetMethodId(msgVal.CSeq.Method, &msgVal.CSeq.MethodId)
			return SGSIPRetOK
		}
	}
	return SGSIPRetNotFound
}

// SGSIPParseMessage --
func SGSIPParseMessage(inputStr string, msgVal *SGSIPMessage) int {
	ret := SGSIPParseFirstLine(inputStr, &msgVal.FLine)
	if ret != SGSIPRetOK {
		return ret
	}
	if msgVal.FLine.MType == FLineRequest {
		ret = SGSIPParseURI(msgVal.FLine.URI, &msgVal.RURI)
		if ret != SGSIPRetOK {
			return ret
		}
	}
	ret = SGSIPParseHeaders(inputStr, 0, &msgVal.Headers)
	if ret != SGSIPRetOK {
		return ret
	}
	ret = SGSIPMessageCSeqParse(msgVal)
	if ret != SGSIPRetOK {
		return ret
	}
	return SGSIPParseBody(inputStr, &msgVal.Body)
}

// SGSIPMessageToString --
func SGSIPMessageToString(msgVal *SGSIPMessage, outputStr *string) int {
	var sb strings.Builder
	if len(msgVal.FLine.Val) == 0 || len(msgVal.Headers) == 0 {
		return SGSIPRetErrMessageNotSet
	}
	sb.WriteString(msgVal.FLine.Val + "\r\n")

	if (msgVal.MFlags&SGSIPMFlagLateOffer) == 0 && msgVal.Body.ContentLen > 0 {
		SGSIPMessageHeaderSet(msgVal, "Content-Length", strconv.Itoa(msgVal.Body.ContentLen))
		if len(msgVal.Body.ContentType) > 0 {
			SGSIPMessageHeaderSet(msgVal, "Content-Type", msgVal.Body.ContentType)
		}
	}

	for _, h := range msgVal.Headers {
		sb.WriteString(h.Name + ": " + h.Body + "\r\n")
	}
	sb.WriteString("\r\n")

	if (msgVal.MFlags&SGSIPMFlagLateOffer) == 0 && msgVal.Body.ContentLen > 0 {
		sb.WriteString(msgVal.Body.Content)
	}

	*outputStr = sb.String()
	return SGSIPRetOK
}

// SGSIPInviteToACKString --
func SGSIPInviteToACKString(invReq *SGSIPMessage, invRpl *SGSIPMessage, outputStr *string) int {
	var sb strings.Builder
	if len(invReq.FLine.Val) == 0 || len(invReq.Headers) == 0 ||
		len(invRpl.FLine.Val) == 0 || len(invRpl.Headers) == 0 {
		return SGSIPRetErrMessageNotSet
	}
	if invRpl.FLine.Code >= 200 && invRpl.FLine.Code < 300 {
		var cturi string = ""
		ret := SGSIPMessageGetContactURI(invRpl, &cturi)
		if ret != SGSIPRetOK {
			return ret
		}
		sb.WriteString("ACK " + cturi + " SIP/2.0\r\n")
	} else if invRpl.FLine.Code >= 300 {
		sb.WriteString("ACK " + invReq.FLine.URI + " SIP/2.0\r\n")
	}
	for _, h := range invReq.Headers {
		switch h.HType {
		case HeaderTypeVia:
			if invRpl.FLine.Code >= 300 {
				sb.WriteString(h.Name + ": " + h.Body + "\r\n")
			} else {
				sList := strings.SplitN(h.Body, ";branch=", 2)
				if len(sList) < 2 {
					sb.WriteString(h.Name + ": " + h.Body + "\r\n")
				} else {
					idxSCol := strings.Index(sList[1], ";")
					if idxSCol < 0 {
						sb.WriteString(h.Name + ": " + sList[0] + ";branch=" +
							viaBranchCookie + uuid.New().String() + "\r\n")
					} else {
						sb.WriteString(h.Name + ": " + sList[0] + ";branch=" +
							viaBranchCookie + uuid.New().String() + sList[1][idxSCol:] + "\r\n")
					}
				}
			}
		case HeaderTypeFrom:
			sb.WriteString(h.Name + ": " + h.Body + "\r\n")
		}
	}
	for _, h := range invRpl.Headers {
		switch h.HType {
		case HeaderTypeTo:
			sb.WriteString(h.Name + ": " + h.Body + "\r\n")
		}
	}
	for _, h := range invReq.Headers {
		switch h.HType {
		case HeaderTypeCallID:
			sb.WriteString(h.Name + ": " + h.Body + "\r\n")
		}
	}
	for _, h := range invRpl.Headers {
		switch h.HType {
		case HeaderTypeCSeq:
			sList := strings.SplitN(h.Body, " ", 2)
			sb.WriteString(h.Name + ": " + sList[0] + " ACK\r\n")
		}
	}

	// reverse walking for route headers
	last := len(invRpl.Headers) - 1
	for i := range invRpl.Headers {
		switch invRpl.Headers[last-i].HType {
		case HeaderTypeRecordRoute:
			// Split by comma in case of comma-separated RR hops.

			rrChunks := strings.Split(invRpl.Headers[last-i].Body, ",")
			lastRRChunk := len(rrChunks) - 1

			for j := range rrChunks {
				sb.WriteString("Route: " + strings.TrimSpace(rrChunks[lastRRChunk-j]) + "\r\n")
			}
		}
	}

	// add authentication headers
	for _, h := range invReq.Headers {
		switch h.HType {
		case HeaderTypeAuthorization:
			sb.WriteString(h.Name + ": " + h.Body + "\r\n")
		case HeaderTypeProxyAuthorization:
			sb.WriteString(h.Name + ": " + h.Body + "\r\n")
		}
	}

	if (invReq.MFlags&SGSIPMFlagLateOffer) != 0 && invReq.Body.ContentLen > 0 &&
		(invRpl.FLine.Code >= 200 && invRpl.FLine.Code < 300) {
		sb.WriteString("Content-Length: " + strconv.Itoa(invReq.Body.ContentLen) + "\r\n")
		if len(invReq.Body.ContentType) > 0 {
			sb.WriteString("Content-Type: " + invReq.Body.ContentType + "\r\n")
		}
		sb.WriteString("\r\n")
		sb.WriteString(invReq.Body.Content)
	} else {
		sb.WriteString("Content-Length: 0\r\n\r\n")
	}
	*outputStr = sb.String()
	return SGSIPRetOK
}

// SGSIPACKToByeString --
func SGSIPACKToByeString(ackReq *SGSIPMessage, outputStr *string) int {
	var sb strings.Builder
	if len(ackReq.FLine.Val) == 0 || len(ackReq.Headers) == 0 ||
		len(ackReq.FLine.Val) == 0 || len(ackReq.Headers) == 0 {
		return SGSIPRetErrMessageNotSet
	}
	sb.WriteString("BYE " + ackReq.FLine.URI + " SIP/2.0\r\n")

	for _, h := range ackReq.Headers {
		switch h.HType {
		case HeaderTypeVia:
			sList := strings.SplitN(h.Body, ";branch=", 2)
			if len(sList) < 2 {
				sb.WriteString(h.Name + ": " + h.Body + "\r\n")
			} else {
				idxSCol := strings.Index(sList[1], ";")
				if idxSCol < 0 {
					sb.WriteString(h.Name + ": " + sList[0] + ";branch=" +
						viaBranchCookie + uuid.New().String() + "\r\n")
				} else {
					sb.WriteString(h.Name + ": " + sList[0] + ";branch=" +
						viaBranchCookie + uuid.New().String() + sList[1][idxSCol:] + "\r\n")
				}
			}
		case HeaderTypeFrom, HeaderTypeTo, HeaderTypeCallID, HeaderTypeRoute:
			sb.WriteString(h.Name + ": " + h.Body + "\r\n")
		case HeaderTypeCSeq:
			sList := strings.SplitN(h.Body, " ", 2)
			if len(sList) != 2 {
				return SGSIPRetErrCSeqBody
			}
			csn, err := strconv.Atoi(sList[0])

			if err != nil {
				return SGSIPRetErrCSeqNumber
			}

			sb.WriteString(h.Name + ": " + strconv.Itoa(csn+1) + " BYE\r\n")
		}
	}
	sb.WriteString("Content-Length: 0\r\n\r\n")
	*outputStr = sb.String()
	return SGSIPRetOK
}

func SGSIPMessageToResponseString(sipReq *SGSIPMessage, scode string, sreason string, outputStr *string) int {
	var sb strings.Builder
	if len(sipReq.FLine.Val) == 0 || len(sipReq.Headers) == 0 ||
		len(sipReq.FLine.Val) == 0 || len(sipReq.Headers) == 0 {
		return SGSIPRetErrMessageNotSet
	}

	sb.WriteString("SIP/2.0 " + scode + " " + sreason + "\r\n")
	for _, h := range sipReq.Headers {
		switch h.HType {
		case HeaderTypeVia:
			// todo: process parameters such as rport, ...
			sb.WriteString(h.Name + ": " + h.Body + "\r\n")
		case HeaderTypeFrom:
			sb.WriteString(h.Name + ": " + h.Body + "\r\n")
		}
	}
	for _, h := range sipReq.Headers {
		switch h.HType {
		case HeaderTypeTo:
			if strings.Index(h.Body, ";tag=") > 0 {
				sb.WriteString(h.Name + ": " + h.Body + "\r\n")
			} else {
				sb.WriteString(h.Name + ": " + h.Body + ";tag=" + uuid.New().String() + "\r\n")
			}
		}
	}
	for _, h := range sipReq.Headers {
		switch h.HType {
		case HeaderTypeCallID, HeaderTypeCSeq:
			sb.WriteString(h.Name + ": " + h.Body + "\r\n")
		}
	}
	sb.WriteString("Content-Length: 0\r\n\r\n")

	*outputStr = sb.String()
	return SGSIPRetOK
}

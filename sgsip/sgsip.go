package sgsip

import (
	"net"
	"strconv"
	"strings"
)

// return and error code values
const (
	SGSIPRetOK = 0
	// generic errors
	SGSIPRetErr = -1
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
		sockaddr.atype = AFIPv6
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
	switch strArray[0] {
	case "sip", "SIP":
		uri.schema = "sip"
		uri.schemaid = SchemaSIP
	case "sips", "SIPS":
		uri.schema = "sips"
		uri.schemaid = SchemaSIPS
	case "tel", "TEL":
		uri.schema = "tel"
		uri.schemaid = SchemaTEL
	default:
		return SGSIPRetErr
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
		uri.val = uristr
		if net.ParseIP(uri.addr) == nil {
			uri.atype = AFHost
		}
		uri.atype = AFIPv4
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
		uri.val = uristr
		if net.ParseIP(uri.addr) == nil {
			uri.atype = AFHost
		}
		uri.atype = AFIPv4
		return SGSIPRetOK
	}
	uri.val = uristr
	return SGSIPRetOK
}

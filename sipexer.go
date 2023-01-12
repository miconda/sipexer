/**
 * SIP (RFC3261) Command Line Tool
 * (C) Copyright 2021-2022 Daniel-Constantin Mierla (asipto.com)
 * License: GPLv3
 */

package main

import (
	"bytes"
	"crypto/md5"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/google/uuid"
	"github.com/miconda/sipexer/sgsip"
	"golang.org/x/net/websocket"
)

const sipexerVersion = "1.0.3"

// exit, return and error code values
const (
	SIPExerRetOK   = 0
	SIPExerRetDone = 1
	SIPExerRetErr  = -1

	// errors
	SIPExerErrTemplateRead        = -1000
	SIPExerErrTemplateData        = -1001
	SIPExerErrFieldsFileRead      = -1020
	SIPExerErrFieldsFileFormat    = -1021
	SIPExerErrFieldsDefaultFormat = -1022
	SIPExerErrExpiresValue        = -1030
	SIPExerErrArgumentsNumber     = -1050
	SIPExerErrDestinationFormat   = -1060
	SIPExerErrURIFormat           = -1070
	SIPExerErrSIPMessageFormat    = -1080
	SIPExerErrSIPMessageToString  = -1081
	SIPExerErrSIPMessageFirstLine = -1082
	SIPExerErrSIPMessageResponse  = -1083
	SIPExerErrProtocolUnsuported  = -1090
	SIPExerErrHeaderAuthGet       = -1100
	SIPExerErrHeaderAuthParse     = -1101
	SIPExerErrResolveSrcUDPAddr   = -1120
	SIPExerErrResolveDstUDPAddr   = -1121
	SIPExerErrUDPSocket           = -1122
	SIPExerErrUDPDial             = -1123
	SIPExerErrUDPWrite            = -1124
	SIPExerErrUDPSetTimeout       = -1125
	SIPExerErrUDPICMPTimeout      = -1126
	SIPExerErrUDPReceiveTimeout   = -1127
	SIPExerErrResolveSrcTCPAddr   = -1140
	SIPExerErrResolveDstTCPAddr   = -1141
	SIPExerErrTCPDial             = -1142
	SIPExerErrTCPWrite            = -1143
	SIPExerErrTCPSetWriteTimeout  = -1144
	SIPExerErrTCPSetReadTimeout   = -1145
	SIPExerErrTCPRead             = -1146
	SIPExerErrTLSReadCertificates = -1150
	SIPExerErrTLSDial             = -1151
	SIPExerErrTLSWrite            = -1152
	SIPExerErrTLSSetReadTimeout   = -1153
	SIPExerErrTLSRead             = -1154
	SIPExerErrWSURLFormat         = -1160
	SIPExerErrWSOrigin            = -1161
	SIPExerErrWSDial              = -1162
	SIPExerErrWSWrite             = -1163
	SIPExerErrWSSetReadTimeout    = -1164
	SIPExerErrWSRead              = -1165
	SIPExerErrRandomKey           = -1170
)

var templateDefaultText string = `{{.method}} {{.ruri}} SIP/2.0
Via: SIP/2.0/{{.viaproto}} {{.viaaddr}}{{.rport}};branch=z9hG4bKSG.{{.viabranch}}
From: {{if .fromuri}}{{.fromuri}}{{else}}{{if .fname}}"{{.fname}}" {{end}}<sip:{{if .fuser}}{{.fuser}}@{{end}}{{.fdomain}}>{{end}};tag={{.fromtag}}
To: {{if .touri}}{{.touri}}{{else}}{{if .tname}}"{{.tname}}" {{end}}<sip:{{if .tuser}}{{.tuser}}@{{end}}{{.tdomain}}>{{end}}
Call-ID: {{.callid}}
CSeq: {{.cseqnum}} {{.method}}
{{if .subject}}Subject: {{.subject}}{{else}}$rmeol{{end}}
{{if .date}}Date: {{.date}}{{else}}$rmeol{{end}}
{{if .contacturi}}Contact: {{.contacturi}}{{if .contactparams}};{{.contactparams}}{{end}}{{else}}$rmeol{{end}}
{{if .expires}}Expires: {{.expires}}{{else}}$rmeol{{end}}
{{if .useragent}}User-Agent: {{.useragent}}{{else}}$rmeol{{end}}
Content-Length: 0

`

var templateDefaultMessageBody string = `Hello there!{{if .date}} The date is: {{.date}}.{{end}}`

var templateDefaultInviteBody string = `v=0{{.cr}}
o={{.sdpuser}} {{.sdpsessid}} {{.sdpsessversion}} IN {{.sdpaf}} {{.localip}}{{.cr}}
s=call{{.cr}}
c=IN {{.sdpaf}} {{.localip}}{{.cr}}
t=0 0{{.cr}}
m=audio {{.sdprtpport}} RTP/AVP 0 8 101{{.cr}}
a=rtpmap:0 pcmu/8000{{.cr}}
a=rtpmap:8 pcma/8000{{.cr}}
a=rtpmap:101 telephone-event/8000{{.cr}}
a=sendrecv{{.cr}}
`

var templateBody string = ""

var templateDefaultJSONFields string = `{
	"method": "OPTIONS",
	"fuser": "alice",
	"fdomain": "localhost",
	"tuser": "bob",
	"tdomain": "localhost",
	"viabranch": "$uuid",
	"rport": ";rport",
	"fromtag": "$uuid",
	"callid": "$uuid",
	"cseqnum": "$randseq",
	"date": "$daterfc1123",
	"sdpuser": "sipexer",
	"sdpsessid": "$timestamp",
	"sdpsessversion": "$timestamp",
	"sdpaf": "IP4",
	"sdprtpport": "$rand(20000,40000)"
}`

var templateFields = map[string]map[string]interface{}{
	"FIELDS:EMPTY": {},
}

var incMap = map[string]int{}

const (
	SIPExerDialogInit       = 0
	SIPExerDialogStarted    = 1
	SIPExerDialogEarly      = 2
	SIPExerDialogAnswered   = 3
	SIPExerDialogConfirmed  = 4
	SIPExerDialogCancelled  = 5
	SIPExerDialogTerminated = 6
)

type SIPExerConnUDP struct {
	SrcAddr *net.UDPAddr
	DstAddr *net.UDPAddr
	Conn    *net.UDPConn
}

type SIPExerConnTCP struct {
	SrcAddr *net.TCPAddr
	DstAddr *net.TCPAddr
	Conn    *net.TCPConn
}

type SIPExerConnTLS struct {
	Conn *tls.Conn
}

type SIPExerConnWSS struct {
	Conn *websocket.Conn
}

type SIPExerDialog struct {
	Proto        string
	ProtoId      int
	LocalAddr    string
	TargetAddr   string
	RecvAddr     string
	AType        int
	Method       string
	MethodId     int
	LocalCSeq    int
	State        int
	FirstRequest *sgsip.SGSIPMessage
	LastRequest  *sgsip.SGSIPMessage
	AckRequest   *sgsip.SGSIPMessage
	LastResponse *sgsip.SGSIPMessage
	ConnUDP      *SIPExerConnUDP
	ConnTCP      *SIPExerConnTCP
	ConnTLS      *SIPExerConnTLS
	ConnWSS      *SIPExerConnWSS
	RecvBuf      []byte
	RecvN        int
	TimeoutStep  int
	TimeoutVal   int
	Resend       bool
	SkipAuth     bool
}

type paramFieldsType map[string]string

func (m paramFieldsType) String() string {
	b := new(bytes.Buffer)
	for key, value := range m {
		fmt.Fprintf(b, "%s:%s\n", key, value)
	}
	return b.String()
}

func (m paramFieldsType) Set(value string) error {
	z := strings.SplitN(value, ":", 2)
	if len(z) > 1 {
		m[z[0]] = z[1]
	}
	return nil
}

var paramFields = make(paramFieldsType)

type headerFieldsType [][2]string

func (m *headerFieldsType) String() string {
	b := new(bytes.Buffer)
	for _, z := range *m {
		fmt.Fprintf(b, "%s:%s\n", z[0], z[1])
	}
	return b.String()
}

func (m *headerFieldsType) Set(value string) error {
	z := strings.SplitN(value, ":", 2)
	if len(z) > 1 {
		*m = append(*m, [2]string{z[0], z[1]})
	}
	return nil
}

var headerFields = make(headerFieldsType, 0)

// CLIOptions - structure for command line options
type CLIOptions struct {
	method           string
	register         bool
	message          bool
	options          bool
	invite           bool
	info             bool
	subscribe        bool
	publish          bool
	notify           bool
	ruri             string
	ruser            string
	fuser            string
	fromuri          string
	tuser            string
	fdomain          string
	tdomain          string
	touri            string
	body             string
	nobody           bool
	contenttype      string
	laddr            string
	useragent        string
	template         string
	templatebody     string
	templaterun      bool
	fields           string
	fieldseval       bool
	nocrlf           bool
	flagdefaults     bool
	templatedefaults bool
	timert1          int
	timert2          int
	timeout          int
	timeoutwrite     int
	buffersize       int
	connectudp       bool
	af               int
	setdomains       bool
	setuser          bool
	tlsinsecure      bool
	tlscertificate   string
	tlskey           string
	wsorigin         string
	wsproto          string
	authuser         string
	authapassword    string
	noval            string
	contacturi       string
	contactbuild     bool
	registerparty    bool
	expires          string
	raw              bool
	noparse          bool
	verbosity        int
	nagios           bool
	ha1              bool
	coloroutput      bool
	colormessage     bool
	sessionwait      int
	helpcommands     bool
	dnssrvprint      bool
	lateoffer        bool
	version          bool
}

var cliops = CLIOptions{
	method:           "",
	ruri:             "",
	fuser:            "",
	fromuri:          "",
	tuser:            "",
	touri:            "",
	fdomain:          "",
	tdomain:          "",
	body:             "",
	nobody:           false,
	contenttype:      "",
	laddr:            "",
	useragent:        "",
	template:         "",
	templatebody:     "",
	templaterun:      false,
	fields:           "",
	fieldseval:       false,
	nocrlf:           false,
	flagdefaults:     false,
	templatedefaults: false,
	timert1:          500,
	timert2:          4000,
	timeout:          32000,
	timeoutwrite:     4000,
	buffersize:       32 * 1024,
	connectudp:       false,
	af:               0,
	setdomains:       false,
	setuser:          false,
	tlsinsecure:      false,
	tlscertificate:   "",
	tlskey:           "",
	wsorigin:         "http://127.0.0.1",
	wsproto:          "sip",
	authuser:         "",
	authapassword:    "",
	noval:            "no",
	contacturi:       "",
	contactbuild:     false,
	expires:          "",
	register:         false,
	message:          false,
	options:          false,
	invite:           false,
	info:             false,
	subscribe:        false,
	publish:          false,
	notify:           false,
	registerparty:    false,
	raw:              false,
	noparse:          false,
	verbosity:        2,
	nagios:           false,
	ha1:              false,
	coloroutput:      false,
	colormessage:     false,
	sessionwait:      0,
	dnssrvprint:      false,
	lateoffer:        false,
	helpcommands:     false,
	version:          false,
}

func sipexer_help_commands() {
	fmt.Fprintf(os.Stderr, "  Examples:\n\n")
	fmt.Fprintf(os.Stderr, "    %s sipserver.com\n", filepath.Base(os.Args[0]))
	fmt.Fprintf(os.Stderr, "    %s tcp:sipserver.com:5060\n", filepath.Base(os.Args[0]))
	fmt.Fprintf(os.Stderr, "    %s -sd -xh \"X-My-Header:abcdefgh\" udp:sipserver.com:5060\n", filepath.Base(os.Args[0]))
	fmt.Fprintf(os.Stderr, "    %s -message -mb 'Hello!' -fuser alice -tuser bob -sd udp:sipserver.com:5060\n", filepath.Base(os.Args[0]))
	fmt.Fprintf(os.Stderr, "    %s -message -mb 'Hello!' -fuser alice -fv fname:Alice -tuser bob -fv tname:Bob -sd udp:sipserver.com:5060\n", filepath.Base(os.Args[0]))
	fmt.Fprintf(os.Stderr, "    %s -register -vl 3 -co -com -ex 60 -fuser alice -cb -ap \"abab...\" -ha1 -sd udp:sipserver.com:5060\n", filepath.Base(os.Args[0]))
	fmt.Fprintf(os.Stderr, "    %s -invite -vl 3 -co -com -fuser alice -tuser bob -cb -ap \"abab...\" -ha1 -sw 10000 -sd -su udp:sipserver.com:5060\n", filepath.Base(os.Args[0]))
	fmt.Fprintf(os.Stderr, "\n")
}

func printCLIOptions() {
	type CLIOptionDef struct {
		Ops      []string
		Usage    string
		DefValue string
		VType    string
	}
	var items []CLIOptionDef
	flag.VisitAll(func(f *flag.Flag) {
		var found bool = false
		for idx, it := range items {
			if it.Usage == f.Usage {
				found = true
				it.Ops = append(it.Ops, f.Name)
				items[idx] = it
			}
		}
		if !found {
			items = append(items, CLIOptionDef{
				Ops:      []string{f.Name},
				Usage:    f.Usage,
				DefValue: f.DefValue,
				VType:    fmt.Sprintf("%T", f.Value),
			})
		}
	})
	sort.Slice(items, func(i, j int) bool { return strings.ToLower(items[i].Ops[0]) < strings.ToLower(items[j].Ops[0]) })
	for _, val := range items {
		vtype := val.VType[6 : len(val.VType)-5]
		if vtype[len(vtype)-2:] == "64" {
			vtype = vtype[:len(vtype)-2]
		}
		for _, opt := range val.Ops {
			if vtype == "bool" {
				fmt.Printf("  -%s\n", opt)
			} else {
				fmt.Printf("  -%s %s\n", opt, vtype)
			}
		}
		if vtype != "bool" && len(val.DefValue) > 0 {
			fmt.Printf("      %s [default: %s]\n", val.Usage, val.DefValue)
		} else {
			fmt.Printf("      %s\n", val.Usage)
		}
	}
}

// initialize application components
func init() {
	// command line arguments
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s (v%s):\n\n", filepath.Base(os.Args[0]), sipexerVersion)
		fmt.Fprintf(os.Stderr, "    %s [options] [target]\n\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(os.Stderr, "      * target can be: 'host', 'proto:host', 'host:port', 'proto:host:port' or sip-uri\n")
		fmt.Fprintf(os.Stderr, "      * some options have short and long version\n\n")
		printCLIOptions()
		fmt.Fprintf(os.Stderr, "\n")
		sipexer_help_commands()
		SIPExerExit(1)
	}
	flag.StringVar(&cliops.method, "method", cliops.method, "SIP method")
	flag.StringVar(&cliops.method, "mt", cliops.method, "SIP method")
	flag.StringVar(&cliops.ruri, "ruri", cliops.ruri, "request uri (r-uri)")
	flag.StringVar(&cliops.ruri, "ru", cliops.ruri, "request uri (r-uri)")
	flag.StringVar(&cliops.ruser, "ruser", cliops.ruser, "request uri username for destination proxy address")
	flag.StringVar(&cliops.ruser, "rn", cliops.ruser, "request uri username for destination proxy address")
	flag.StringVar(&cliops.fuser, "fuser", cliops.fuser, "From header URI username")
	flag.StringVar(&cliops.fuser, "fu", cliops.fuser, "From header URI username")
	flag.StringVar(&cliops.tuser, "tuser", cliops.tuser, "To header URI username")
	flag.StringVar(&cliops.tuser, "tu", cliops.tuser, "To header URI username")
	flag.StringVar(&cliops.fdomain, "fdomain", cliops.fdomain, "From header URI domain")
	flag.StringVar(&cliops.fdomain, "fd", cliops.fdomain, "From header URI domain")
	flag.StringVar(&cliops.fromuri, "from-uri", cliops.fromuri, "From header URI")
	flag.StringVar(&cliops.tdomain, "tdomain", cliops.tdomain, "To header URI domain")
	flag.StringVar(&cliops.tdomain, "td", cliops.tdomain, "To header URI domain")
	flag.StringVar(&cliops.touri, "to-uri", cliops.touri, "To header URI")
	flag.StringVar(&cliops.template, "template-file", cliops.template, "path to template file")
	flag.StringVar(&cliops.template, "tf", cliops.template, "path to template file")
	flag.StringVar(&cliops.templatebody, "template-body-file", cliops.templatebody, "path to template file for body")
	flag.StringVar(&cliops.templatebody, "tbf", cliops.templatebody, "path to template file for body")
	flag.StringVar(&cliops.fields, "fields-file", cliops.fields, "path to the json fields file")
	flag.StringVar(&cliops.fields, "ff", cliops.fields, "path to the json fields file")
	flag.StringVar(&cliops.laddr, "laddr", cliops.laddr, "local address (`ip:port` or `:port`)")
	flag.StringVar(&cliops.useragent, "user-agent", cliops.useragent, "user agent value")
	flag.StringVar(&cliops.useragent, "ua", cliops.useragent, "user agent value")
	flag.StringVar(&cliops.tlscertificate, "tls-certificate", cliops.tlscertificate, "path to TLS public certificate")
	flag.StringVar(&cliops.tlscertificate, "tc", cliops.tlscertificate, "path to TLS public certificate")
	flag.StringVar(&cliops.tlskey, "tls-key", cliops.tlskey, "path to TLS private key")
	flag.StringVar(&cliops.tlskey, "tk", cliops.tlskey, "path to TLS private key")
	flag.StringVar(&cliops.body, "message-body", cliops.body, "message body")
	flag.StringVar(&cliops.body, "mb", cliops.body, "message body")
	flag.StringVar(&cliops.contenttype, "content-type", cliops.contenttype, "content type")
	flag.StringVar(&cliops.contenttype, "ct", cliops.contenttype, "content type")
	flag.StringVar(&cliops.wsorigin, "websocket-origin", cliops.wsorigin, "websocket origin http url")
	flag.StringVar(&cliops.wsorigin, "wso", cliops.wsorigin, "websocket origin http url")
	flag.StringVar(&cliops.wsproto, "websocket-proto", cliops.wsproto, "websocket sub-protocol")
	flag.StringVar(&cliops.wsproto, "wsp", cliops.wsproto, "websocket sub-protocol")
	flag.StringVar(&cliops.authuser, "auth-user", cliops.authuser, "authentication user")
	flag.StringVar(&cliops.authuser, "au", cliops.authuser, "authentication user")
	flag.StringVar(&cliops.authapassword, "auth-password", cliops.authapassword, "authentication password")
	flag.StringVar(&cliops.authapassword, "ap", cliops.authapassword, "authentication password")
	flag.StringVar(&cliops.noval, "no-val", cliops.noval, "no value string")
	flag.StringVar(&cliops.contacturi, "contact-uri", cliops.contacturi, "contact uri")
	flag.StringVar(&cliops.contacturi, "cu", cliops.contacturi, "contact uri")
	flag.StringVar(&cliops.expires, "expires", cliops.expires, "expires header value")
	flag.StringVar(&cliops.expires, "ex", cliops.expires, "expires header value")

	flag.BoolVar(&cliops.fieldseval, "fields-eval", cliops.fieldseval, "evaluate expression in fields file")
	flag.BoolVar(&cliops.fieldseval, "fe", cliops.fieldseval, "evaluate expression in fields file")
	flag.BoolVar(&cliops.nocrlf, "no-crlf", cliops.nocrlf, "do not replace '\\n' with '\\r\\n' inside the data to be sent (true|false)")
	flag.BoolVar(&cliops.flagdefaults, "flag-defaults", cliops.flagdefaults, "print flag (cli param) default values")
	flag.BoolVar(&cliops.flagdefaults, "fvd", cliops.flagdefaults, "print flag (cli param) default values")
	flag.BoolVar(&cliops.templatedefaults, "template-defaults", cliops.templatedefaults, "print default (internal) template data")
	flag.BoolVar(&cliops.templatedefaults, "tpd", cliops.templatedefaults, "print default (internal) template data")
	flag.BoolVar(&cliops.templaterun, "template-run", cliops.templaterun, "run template execution and print the result")
	flag.BoolVar(&cliops.templaterun, "tpr", cliops.templaterun, "run template execution and print the result")
	flag.BoolVar(&cliops.connectudp, "connect-udp", cliops.connectudp, "attempt first a connect for UDP (dial ICMP connect)")
	flag.BoolVar(&cliops.setdomains, "set-domains", cliops.setdomains, "set From/To domains based on R-URI")
	flag.BoolVar(&cliops.setdomains, "sd", cliops.setdomains, "set From/To domains based on R-URI")
	flag.BoolVar(&cliops.setuser, "set-user", cliops.setuser, "set R-URI user to To-URI user for destination proxy address")
	flag.BoolVar(&cliops.setuser, "su", cliops.setuser, "set R-URI user to To-URI user for destination proxy address")
	flag.BoolVar(&cliops.tlsinsecure, "tls-insecure", cliops.tlsinsecure, "skip tls certificate validation (true|false)")
	flag.BoolVar(&cliops.tlsinsecure, "ti", cliops.tlsinsecure, "skip tls certificate validation (true|false)")
	flag.BoolVar(&cliops.register, "register", cliops.register, "set method to REGISTER")
	flag.BoolVar(&cliops.register, "r", cliops.register, "set method to REGISTER")
	flag.BoolVar(&cliops.options, "options", cliops.options, "set method to OPTIONS")
	flag.BoolVar(&cliops.options, "o", cliops.options, "set method to OPTIONS")
	flag.BoolVar(&cliops.message, "message", cliops.message, "set method to MESSAGE")
	flag.BoolVar(&cliops.message, "m", cliops.message, "set method to MESSAGE")
	flag.BoolVar(&cliops.invite, "invite", cliops.invite, "set method to INVITE")
	flag.BoolVar(&cliops.invite, "i", cliops.invite, "set method to INVITE")
	flag.BoolVar(&cliops.info, "info", cliops.info, "set method to INFO")
	flag.BoolVar(&cliops.publish, "publish", cliops.publish, "set method to PUBLISH")
	flag.BoolVar(&cliops.subscribe, "subscribe", cliops.subscribe, "set method to SUBSCRIBE")
	flag.BoolVar(&cliops.notify, "notify", cliops.notify, "set method to NOTIFY")
	flag.BoolVar(&cliops.contactbuild, "contact-build", cliops.contactbuild, "build contact header based on local address")
	flag.BoolVar(&cliops.contactbuild, "cb", cliops.contactbuild, "build contact header based on local address")
	flag.BoolVar(&cliops.registerparty, "register-party", cliops.registerparty, "register a third party To user")
	flag.BoolVar(&cliops.raw, "raw", cliops.registerparty, "sent raw template content (no evaluation)")
	flag.BoolVar(&cliops.noparse, "no-parse", cliops.noparse, "no SIP message parsing of input template result")
	flag.BoolVar(&cliops.nagios, "nagios", cliops.nagios, "nagios plugin exit codes")
	flag.BoolVar(&cliops.ha1, "ha1", cliops.ha1, "authentication password is in HA1 format")
	flag.BoolVar(&cliops.nobody, "no-body", cliops.nobody, "no body for message or invite")
	flag.BoolVar(&cliops.coloroutput, "color-output", cliops.coloroutput, "color output")
	flag.BoolVar(&cliops.coloroutput, "co", cliops.coloroutput, "color output")
	flag.BoolVar(&cliops.colormessage, "color-message", cliops.colormessage, "color SIP message output")
	flag.BoolVar(&cliops.colormessage, "com", cliops.colormessage, "color SIP message output")

	flag.IntVar(&cliops.timert1, "timer-t1", cliops.timert1, "value of t1 timer (milliseconds)")
	flag.IntVar(&cliops.timert2, "timer-t2", cliops.timert2, "value of t2 timer (milliseconds)")
	flag.IntVar(&cliops.timeoutwrite, "timeout-write", cliops.timeoutwrite, "timeout to write data to socket (milliseconds)")
	flag.IntVar(&cliops.timeout, "timeout", cliops.timeout, "timeout waiting to receice data (milliseconds)")
	flag.IntVar(&cliops.af, "af", cliops.af, "enforce address family for socket (4 or 6)")
	flag.IntVar(&cliops.verbosity, "verbosity", cliops.verbosity, "verbosity level (0..3)")
	flag.IntVar(&cliops.verbosity, "vl", cliops.verbosity, "verbosity level (0..3)")
	flag.IntVar(&cliops.sessionwait, "sessionwait", cliops.sessionwait, "time in millisecons to wait for a session")
	flag.IntVar(&cliops.sessionwait, "sw", cliops.sessionwait, "time in millisecons to wait for a session")

	flag.Var(&paramFields, "field-val", "field value in format 'name:value' (can be provided many times)")
	flag.Var(&paramFields, "fv", "field value in format 'name:value' (can be provided many times)")

	flag.Var(&headerFields, "extra-header", "extra header in format 'name:body' (can be provided many times)")
	flag.Var(&headerFields, "xh", "extra header in format 'name:body' (can be provided many times)")

	flag.BoolVar(&cliops.dnssrvprint, "dns-srv-print", cliops.dnssrvprint, "print DNS SRV records")

	flag.BoolVar(&cliops.lateoffer, "late-offer", cliops.lateoffer, "enable SDP late offer mode")

	flag.BoolVar(&cliops.helpcommands, "help-commands", cliops.helpcommands, "print help with command examples")
	flag.BoolVar(&cliops.helpcommands, "hc", cliops.helpcommands, "print help with command examples")
	flag.BoolVar(&cliops.version, "version", cliops.version, "print version")
	flag.BoolVar(&cliops.version, "v", cliops.version, "print version")

	rand.Seed(time.Now().UnixNano())

}

// sipexer application
func main() {
	var err error
	var ival int
	var ok bool

	flag.Parse()

	fmt.Printf("\n")

	if cliops.version {
		fmt.Printf("%s v%s\n\n", filepath.Base(os.Args[0]), sipexerVersion)
		SIPExerExit(SIPExerRetDone)
	}
	if cliops.helpcommands {
		sipexer_help_commands()
		SIPExerExit(SIPExerRetDone)
	}
	if cliops.templatedefaults {
		fmt.Printf("  - Default SIP request template:\n\n")
		fmt.Println(templateDefaultText)
		fmt.Printf("\n  - Default field values:\n\n")
		fmt.Println(templateDefaultJSONFields)
		fmt.Printf("\n  - Default SIP MESSAGE body template:\n\n")
		fmt.Println(templateDefaultMessageBody)
		fmt.Printf("\n  - Default SIP INVITE body template:\n\n")
		fmt.Println(templateDefaultInviteBody)
		SIPExerExit(SIPExerRetDone)
	}
	if cliops.flagdefaults {
		flag.PrintDefaults()
		SIPExerExit(SIPExerRetDone)
	}
	// enable file name and line numbers in logging
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	if cliops.dnssrvprint {
		if len(flag.Args()) < 1 {
			SIPExerPrintf(SIPExerLogError, "domain argument not provided\n")
			SIPExerExit(SIPExerRetErr)
		}
		var dqProtos []string
		if len(flag.Args()) == 1 {
			dqProtos = append(dqProtos, "udp", "tcp", "tls", "sctp")
		} else {
			dqProtos = append(dqProtos, flag.Arg(0))
		}
		for _, proto := range dqProtos {
			cname, srvs, err := net.LookupSRV("sip", proto, flag.Arg(len(flag.Args())-1))
			if err != nil {
				SIPExerPrintf(SIPExerLogError, "\nerror: %v\n\n", err)
			} else {
				fmt.Printf("cname: %s\n", cname)
				for _, srv := range srvs {
					fmt.Printf("_sip.%s.%s => %v:%v (%d:%d)\n", proto, flag.Arg(len(flag.Args())-1),
						srv.Target, srv.Port, srv.Priority, srv.Weight)
				}
			}
		}
		SIPExerExit(SIPExerRetDone)
	}

	var tplstr = ""
	if len(cliops.template) > 0 {
		tpldata, err1 := ioutil.ReadFile(cliops.template)
		if err1 != nil {
			SIPExerPrintf(SIPExerLogError, "error: %v\n", err1)
			SIPExerExit(SIPExerErrTemplateRead)
		}
		tplstr = string(tpldata)
	} else if len(templateDefaultText) > 0 {
		tplstr = templateDefaultText
	} else {
		SIPExerPrintf(SIPExerLogError, "missing data template file ('-tf' or '--template' parameter must be provided)\n")
		SIPExerExit(SIPExerErrTemplateData)
	}

	if len(cliops.templatebody) > 0 {
		tpldata, err1 := ioutil.ReadFile(cliops.templatebody)
		if err1 != nil {
			SIPExerPrintf(SIPExerLogError, "error: %v\n", err1)
			SIPExerExit(SIPExerErrTemplateRead)
		}
		templateBody = string(tpldata)
	}

	tplfields := make(map[string]interface{})
	if len(cliops.fields) > 0 {
		fieldsdata, err1 := ioutil.ReadFile(cliops.fields)
		if err1 != nil {
			SIPExerPrintf(SIPExerLogError, "error: %v\n", err1)
			SIPExerExit(SIPExerErrFieldsFileRead)
		}
		err = json.Unmarshal(fieldsdata, &tplfields)
		if err != nil {
			SIPExerPrintf(SIPExerLogError, "error: %v\n", err)
			SIPExerExit(SIPExerErrFieldsFileFormat)
		}
	} else if len(templateDefaultJSONFields) > 0 {
		err = json.Unmarshal([]byte(templateDefaultJSONFields), &tplfields)
		if err != nil {
			SIPExerPrintf(SIPExerLogError, "error: %v\n", err)
			SIPExerExit(SIPExerErrFieldsDefaultFormat)
		}
		cliops.fieldseval = true
	} else {
		tplfields = templateFields["FIELDS:EMPTY"]
	}
	if cliops.fieldseval {
		for k := range tplfields {
			switch tplfields[k].(type) {
			case string:
				if tplfields[k] == "$uuid" {
					tplfields[k] = uuid.New().String()
				} else if tplfields[k] == "$randseq" {
					tplfields[k] = strconv.Itoa(1 + mathrand.Intn(999999))
				} else if tplfields[k] == "$datefull" {
					tplfields[k] = time.Now().String()
				} else if tplfields[k] == "$daterfc1123" {
					tplfields[k] = time.Now().Format(time.RFC1123)
				} else if tplfields[k] == "$dateunix" {
					tplfields[k] = time.Now().Format(time.UnixDate)
				} else if tplfields[k] == "$dateansic" {
					tplfields[k] = time.Now().Format(time.ANSIC)
				} else if tplfields[k] == "$timestamp" {
					tplfields[k] = strconv.FormatInt(time.Now().Unix(), 10)
				} else if tplfields[k] == "$pid" {
					tplfields[k] = strconv.Itoa(os.Getpid())
				} else if tplfields[k] == "$cr" {
					tplfields[k] = "\r"
				} else if tplfields[k] == "$lf" {
					tplfields[k] = "\n"
				} else {
					sVal := fmt.Sprint(tplfields[k])
					if strings.Index(sVal, "$rand(") == 0 && strings.LastIndex(sVal, ")") == len(sVal)-1 {
						sVal = sVal[6 : len(sVal)-1]
						sArr := strings.Split(sVal, ",")
						if len(sArr) == 1 {
							nVal, _ := strconv.Atoi(sArr[0])
							tplfields[k] = strconv.Itoa(mathrand.Intn(nVal))
						} else {
							nValA, _ := strconv.Atoi(sArr[0])
							nValB, _ := strconv.Atoi(sArr[1])
							tplfields[k] = strconv.Itoa(nValA + mathrand.Intn(nValB-nValA))
						}
					} else if strings.Index(sVal, "$randstr(") == 0 && strings.LastIndex(sVal, ")") == len(sVal)-1 {
						sVal = sVal[9 : len(sVal)-1]
						sArr := strings.Split(sVal, ",")
						if len(sArr) == 1 {
							nVal, _ := strconv.Atoi(sArr[0])
							tplfields[k] = SIPExerRandAlphaString(nVal)
						} else {
							nValA, _ := strconv.Atoi(sArr[0])
							nValB, _ := strconv.Atoi(sArr[1])
							tplfields[k] = SIPExerRandAlphaString(nValA + mathrand.Intn(nValB-nValA))
						}
					} else if strings.Index(sVal, "$randan(") == 0 && strings.LastIndex(sVal, ")") == len(sVal)-1 {
						sVal = sVal[9 : len(sVal)-1]
						sArr := strings.Split(sVal, ",")
						if len(sArr) == 1 {
							nVal, _ := strconv.Atoi(sArr[0])
							tplfields[k] = SIPExerRandAlphaNumString(nVal)
						} else {
							nValA, _ := strconv.Atoi(sArr[0])
							nValB, _ := strconv.Atoi(sArr[1])
							tplfields[k] = SIPExerRandAlphaNumString(nValA + mathrand.Intn(nValB-nValA))
						}
					} else if strings.Index(sVal, "$randnum(") == 0 && strings.LastIndex(sVal, ")") == len(sVal)-1 {
						sVal = sVal[9 : len(sVal)-1]
						sArr := strings.Split(sVal, ",")
						if len(sArr) == 1 {
							nVal, _ := strconv.Atoi(sArr[0])
							tplfields[k] = SIPExerRandNumString(nVal)
						} else {
							nValA, _ := strconv.Atoi(sArr[0])
							nValB, _ := strconv.Atoi(sArr[1])
							tplfields[k] = SIPExerRandNumString(nValA + mathrand.Intn(nValB-nValA))
						}
					} else if strings.Index(sVal, "$randhex(") == 0 && strings.LastIndex(sVal, ")") == len(sVal)-1 {
						sVal = sVal[9 : len(sVal)-1]
						sArr := strings.Split(sVal, ",")
						if len(sArr) == 1 {
							nVal, _ := strconv.Atoi(sArr[0])
							tplfields[k] = SIPExerRandHexString(nVal)
						} else {
							nValA, _ := strconv.Atoi(sArr[0])
							nValB, _ := strconv.Atoi(sArr[1])
							tplfields[k] = SIPExerRandHexString(nValA + mathrand.Intn(nValB-nValA))
						}
					} else if strings.Index(sVal, "$env(") == 0 && strings.LastIndex(sVal, ")") == len(sVal)-1 {
						eVal, ok := os.LookupEnv(sVal[5 : len(sVal)-1])
						if ok {
							tplfields[k] = eVal
						}
					} else if strings.Index(sVal, "$inc(") == 0 && strings.LastIndex(sVal, ")") == len(sVal)-1 {
						eVal, ok := incMap[sVal[5:len(sVal)-1]]
						if !ok {
							eVal = 0
						}
						eVal++
						incMap[sVal[5:len(sVal)-1]] = eVal
						tplfields[k] = strconv.Itoa(eVal)
					}
				}
				break
			}
		}
	}
	if len(paramFields) > 0 {
		for k := range paramFields {
			if k == "rport" {
				if strings.Trim(paramFields[k], " \t\r\n") == cliops.noval {
					tplfields[k] = ""
				}
			} else if k == "date" {
				if strings.Trim(paramFields[k], " \t\r\n") == cliops.noval {
					delete(tplfields, "date")
				}
			} else {
				tplfields[k] = paramFields[k]
			}
		}
	}

	if cliops.register {
		tplfields["method"] = "REGISTER"
	} else if cliops.message {
		tplfields["method"] = "MESSAGE"
	} else if cliops.options {
		tplfields["method"] = "OPTIONS"
	} else if cliops.invite {
		tplfields["method"] = "INVITE"
	} else if cliops.info {
		tplfields["method"] = "INFO"
	} else if cliops.subscribe {
		tplfields["method"] = "SUBSCRIBE"
	} else if cliops.publish {
		tplfields["method"] = "PUBLISH"
	} else if cliops.notify {
		tplfields["method"] = "NOTIFY"
	} else if len(cliops.method) > 0 {
		tplfields["method"] = strings.ToUpper(cliops.method)
	}

	// cli flags updates when sip method is set via field value parameter
	tplMethod := fmt.Sprint(tplfields["method"])
	if !cliops.options && tplMethod == "OPTIONS" {
		cliops.options = true
	} else if !cliops.invite && tplMethod == "INVITE" {
		cliops.invite = true
	} else if !cliops.register && tplMethod == "REGISTER" {
		cliops.register = true
	}

	if len(cliops.expires) > 0 {
		ival, err = strconv.Atoi(cliops.expires)
		if err != nil || ival < 0 {
			SIPExerPrintf(SIPExerLogError, "invalid expires value: %s\n", cliops.expires)
			SIPExerExit(SIPExerErrExpiresValue)
		}
		tplfields["expires"] = cliops.expires
	}
	_, ok = tplfields["contacturi"]
	if !ok {
		if len(cliops.contacturi) > 0 {
			if cliops.contacturi[0:1] == "<" && cliops.contacturi[len(cliops.contacturi)-1:] == ">" {
				tplfields["contacturi"] = cliops.contacturi
			} else {
				tplfields["contacturi"] = "<" + cliops.contacturi + ">"
			}
		}
	}
	if len(cliops.fuser) > 0 {
		tplfields["fuser"] = cliops.fuser
	}
	if len(cliops.tuser) > 0 {
		tplfields["tuser"] = cliops.tuser
	}
	if len(cliops.fdomain) > 0 {
		tplfields["fdomain"] = cliops.fdomain
	}
	if len(cliops.tdomain) > 0 {
		tplfields["tdomain"] = cliops.tdomain
	}
	if len(cliops.fromuri) > 0 {
		if cliops.fromuri[0:1] == "<" {
			tplfields["fromuri"] = cliops.fromuri
		} else {
			tplfields["fromuri"] = "<" + cliops.fromuri + ">"
		}
	}

	if len(cliops.touri) > 0 {
		if cliops.touri[0:1] == "<" {
			tplfields["touri"] = cliops.touri
		} else {
			tplfields["touri"] = "<" + cliops.touri + ">"
		}
	}

	if len(cliops.useragent) > 0 {
		if cliops.useragent != cliops.noval {
			tplfields["useragent"] = cliops.useragent
		}
	} else {
		tplfields["useragent"] = "SIPExer v" + sipexerVersion
	}

	// delete `cliops.noval` fields
	_, ok = tplfields["fuser"]
	if ok && tplfields["fuser"] == cliops.noval {
		delete(tplfields, "fuser")
	}
	_, ok = tplfields["tuser"]
	if ok && tplfields["tuser"] == cliops.noval {
		delete(tplfields, "tuser")
	}

	var wsurlp *url.URL = nil
	dstAddr := "udp:127.0.0.1:5060"
	if len(flag.Args()) > 0 {
		if len(flag.Args()) == 1 {
			dstAddr = flag.Arg(0)
			if strings.HasPrefix(dstAddr, "wss://") ||
				strings.HasPrefix(dstAddr, "ws://") {
				wsurlp, err = url.Parse(dstAddr)
				if err != nil {
					SIPExerPrintf(SIPExerLogError, "invalid websocket target: %v\n", dstAddr)
					SIPExerExit(SIPExerErrWSURLFormat)
				}
				if strings.HasPrefix(dstAddr, "wss://") {
					dstAddr = "wss:" + wsurlp.Host
				} else {
					dstAddr = "ws:" + wsurlp.Host
				}
			}
		} else if len(flag.Args()) == 2 {
			dstAddr = "udp:" + flag.Arg(0) + ":" + flag.Arg(1)
		} else if len(flag.Args()) == 3 {
			dstAddr = flag.Arg(0) + ":" + flag.Arg(1) + ":" + flag.Arg(2)
		} else {
			SIPExerPrintf(SIPExerLogError, "invalid number of arguments : %d\n", len(flag.Args()))
			SIPExerExit(SIPExerErrArgumentsNumber)
		}
	}
	var dstSockAddr = sgsip.SGSIPSocketAddress{}
	var dstURI = sgsip.SGSIPURI{}
	if sgsip.SGSIPParseSocketAddress(dstAddr, &dstSockAddr) != sgsip.SGSIPRetOK {
		if sgsip.SGSIPParseURI(dstAddr, &dstURI) != sgsip.SGSIPRetOK {
			SIPExerPrintf(SIPExerLogError, "invalid destination address: %s\n", dstAddr)
			SIPExerExit(SIPExerErrDestinationFormat)
		} else {
			SIPExerPrintf(SIPExerLogDebug, "parsed SIP URI argument (%+v)\n", dstURI)
			sgsip.SGSIPURIToSocketAddress(&dstURI, &dstSockAddr)
		}
	} else {
		SIPExerPrintf(SIPExerLogDebug, "parsed socket address argument (%+v)\n", dstSockAddr)
		if cliops.setuser {
			_, ok = tplfields["tuser"]
			if ok {
				sgsip.SGSocketAddressToSIPURI(&dstSockAddr, fmt.Sprint(tplfields["tuser"]), 0, &dstURI)
			} else {
				sgsip.SGSocketAddressToSIPURI(&dstSockAddr, cliops.ruser, 0, &dstURI)
			}
		} else {
			sgsip.SGSocketAddressToSIPURI(&dstSockAddr, cliops.ruser, 0, &dstURI)
		}
	}
	if len(cliops.ruri) > 0 {
		tplfields["ruri"] = cliops.ruri
	} else {
		_, ok = tplfields["ruri"]
		if !ok {
			tplfields["ruri"] = dstURI.Val
		}
	}
	if cliops.setdomains {
		var rURI = sgsip.SGSIPURI{}
		if sgsip.SGSIPParseURI(fmt.Sprint(tplfields["ruri"]), &rURI) != sgsip.SGSIPRetOK {
			SIPExerPrintf(SIPExerLogError, "invalid ruri: %v\n", tplfields["ruri"])
			SIPExerExit(SIPExerErrURIFormat)
		}
		tplfields["fdomain"] = rURI.Addr
		tplfields["tdomain"] = rURI.Addr
	}

	var tret int
	if cliops.templaterun {
		lTAddr := ""
		if len(cliops.laddr) > 0 {
			lTAddr = cliops.laddr
		} else {
			lTAddr = "127.0.0.1:55060"
		}
		var msgVal sgsip.SGSIPMessage = sgsip.SGSIPMessage{}
		var smsg string = ""
		tret = SIPExerPrepareMessage(tplstr, tplfields, dstSockAddr.Proto, lTAddr, dstSockAddr.Addr+":"+dstSockAddr.Port, &msgVal)
		if tret != 0 {
			SIPExerExit(tret)
		}
		smsg = msgVal.Data
		msgVal = sgsip.SGSIPMessage{}
		if sgsip.SGSIPParseMessage(smsg, &msgVal) != sgsip.SGSIPRetOK {
			SIPExerPrintf(SIPExerLogError, "failed to parse sip message\n%+v\n\n", smsg)
			SIPExerExit(SIPExerErrSIPMessageFormat)
		}
		if cliops.verbosity > 0 {
			fmt.Printf("%+v\n\n", smsg)
			fmt.Printf("%+v\n\n", msgVal)
		}

		SIPExerExit(SIPExerRetDone)
	}

	if (dstSockAddr.ProtoId != sgsip.ProtoUDP) && (dstSockAddr.ProtoId != sgsip.ProtoTCP) &&
		(dstSockAddr.ProtoId != sgsip.ProtoTLS) && (dstSockAddr.ProtoId != sgsip.ProtoWSS) {
		SIPExerPrintf(SIPExerLogError, "transport protocol not supported yet for target %s\n", dstAddr)
		SIPExerExit(SIPExerErrProtocolUnsuported)
	}

	tchan := make(chan int, 1)
	if dstSockAddr.ProtoId == sgsip.ProtoTCP {
		go SIPExerSendTCP(dstSockAddr, tplstr, tplfields, tchan)
	} else if dstSockAddr.ProtoId == sgsip.ProtoTLS {
		go SIPExerSendTLS(dstSockAddr, tplstr, tplfields, tchan)
	} else if dstSockAddr.ProtoId == sgsip.ProtoWSS {
		go SIPExerSendWSS(dstSockAddr, wsurlp, tplstr, tplfields, tchan)
	} else {
		go SIPExerSendUDP(dstSockAddr, tplstr, tplfields, tchan)
	}
	tret = <-tchan
	close(tchan)

	SIPExerExit(tret)
}

func SIPExerExit(ret int) {
	var nret int

	nret = ret

	if cliops.nagios {
		if ret == SIPExerRetOK || ret == SIPExerRetDone || (ret >= 200 && ret <= 299) {
			nret = 0
		} else if ret >= 400 && ret <= 499 {
			nret = 1
		} else {
			nret = 3
		}
	}
	if ret != nret {
		SIPExerPrintf(SIPExerLogDebug, "initial return code: %d\n\n", ret)
	}
	SIPExerPrintf(SIPExerLogDebug, "return code: %d\n\n", nret)

	os.Exit(nret)
}

func SIPExerPrepareMessage(tplstr string, tplfields map[string]interface{}, rProto string, lAddr string, rAddr string, msgVal *sgsip.SGSIPMessage) int {
	var buf bytes.Buffer
	var tpl = template.Must(template.New("wsout").Parse(tplstr))
	var msgrebuild bool = false
	var ok bool = false

	if cliops.raw {
		msgVal.Data = tplstr
		return SIPExerRetOK
	}

	tplfields["proto"] = strings.ToLower(rProto)
	tplfields["protoup"] = strings.ToUpper(rProto)
	tplfields["localaddr"] = lAddr
	colPos := strings.LastIndex(lAddr, ":")
	tplfields["localip"] = lAddr[0:colPos]
	tplfields["localport"] = lAddr[colPos+1:]
	tplfields["targetaddr"] = rAddr
	colPos = strings.LastIndex(rAddr, ":")
	tplfields["targetip"] = rAddr[0:colPos]
	tplfields["targetport"] = rAddr[colPos+1:]
	if sgsip.SGAddrTypeEx(rAddr[0:colPos]) == sgsip.AFIPv6 {
		tplfields["afver"] = "6"
		tplfields["sdpaf"] = "IP6"
	} else {
		tplfields["afver"] = "4"
		tplfields["sdpaf"] = "IP4"
	}
	tplfields["cr"] = "\r"
	tplfields["lf"] = "\n"
	tplfields["tab"] = "\t"

	_, ok = tplfields["viaaddr"]
	if !ok {
		tplfields["viaaddr"] = lAddr
	}
	_, ok = tplfields["viaproto"]
	if !ok {
		tplfields["viaproto"] = strings.ToUpper(rProto)
	}

	if cliops.register && !cliops.registerparty {
		_, ok = tplfields["fname"]
		if ok {
			tplfields["tname"] = tplfields["fname"]
		}
		tplfields["tuser"] = tplfields["fuser"]
		tplfields["tdomain"] = tplfields["fdomain"]
	}

	if cliops.contactbuild {
		tplfields["contacturi"] = "<sip:" + lAddr + ";transport=" + strings.ToLower(rProto) + ">"
	}

	tpl.Execute(&buf, tplfields)

	var smsg string
	smsg = strings.Replace(buf.String(), "$rmeol\n", "", -1)
	if !cliops.nocrlf {
		eohPos := strings.Index(smsg, "\r\n\r\n")
		if eohPos < 0 {
			// replace LF (\n) with CRLF (\r\n) over the headers part
			eohPos = strings.Index(smsg, "\n\n")
			if eohPos < 0 {
				// set proper end of headers
				if smsg[len(smsg)-1:] == "\n" {
					smsg += "\n"
				} else {
					smsg += "\n\n"
				}
				smsg = strings.Replace(smsg, "\n", "\r\n", -1)
			} else {
				if eohPos == len(smsg)-2 {
					smsg = strings.Replace(smsg, "\n", "\r\n", -1)
				} else {
					smsg = strings.Replace(smsg[0:eohPos+2], "\n", "\r\n", -1) + smsg[eohPos+2:]
				}
			}
		}
	}

	if cliops.noparse {
		msgVal.Data = smsg
		return SIPExerRetOK
	}

	if sgsip.SGSIPParseMessage(smsg, msgVal) != sgsip.SGSIPRetOK {
		SIPExerPrintf(SIPExerLogError, "failed to parse sip message\n%+v\n\n", smsg)
		return SIPExerErrSIPMessageFormat
	}

	if len(headerFields) > 0 {
		for _, hdrs := range headerFields {
			var hdrItem sgsip.SGSIPHeader = sgsip.SGSIPHeader{}
			hdrItem.Name = hdrs[0]
			hdrItem.Body = hdrs[1]
			msgVal.Headers = append(msgVal.Headers, hdrItem)
		}
		msgrebuild = true
	}
	if !cliops.nobody {
		if len(cliops.body) > 0 {
			msgVal.Body.Content = cliops.body
		} else if len(templateBody) > 0 {
			var bufBody bytes.Buffer
			var tplBody = template.Must(template.New("wbodyout").Parse(templateBody))
			tplBody.Execute(&bufBody, tplfields)
			msgVal.Body.Content = strings.Replace(bufBody.String(), "$rmeol\n", "", -1)
		} else if cliops.message {
			var bufBody bytes.Buffer
			var tplBody = template.Must(template.New("wbodyout").Parse(templateDefaultMessageBody))
			tplBody.Execute(&bufBody, tplfields)
			msgVal.Body.Content = strings.Replace(bufBody.String(), "$rmeol\n", "", -1)
		} else if cliops.invite {
			var bufBody bytes.Buffer
			var tplBody = template.Must(template.New("wbodyout").Parse(templateDefaultInviteBody))
			tplBody.Execute(&bufBody, tplfields)
			msgVal.Body.Content = strings.Replace(bufBody.String(), "$rmeol\n", "", -1)
			if cliops.lateoffer {
				msgVal.MFlags = msgVal.MFlags | sgsip.SGSIPMFlagLateOffer
			}
		}

		if len(msgVal.Body.Content) > 0 {
			msgVal.Body.ContentLen = len(msgVal.Body.Content)
			if len(cliops.contenttype) > 0 {
				msgVal.Body.ContentType = cliops.contenttype
			} else {
				if cliops.invite {
					msgVal.Body.ContentType = "application/sdp"
				} else {
					msgVal.Body.ContentType = "text/plain"
				}
			}
			msgrebuild = true
		}
	}

	if msgrebuild {
		if sgsip.SGSIPMessageToString(msgVal, &smsg) != sgsip.SGSIPRetOK {
			SIPExerPrintf(SIPExerLogError, "failed to rebuild sip message\n")
			return SIPExerErrSIPMessageToString
		}
	}
	msgVal.Data = smsg
	return SIPExerRetOK
}

func SIPExerProcessResponse(msgVal *sgsip.SGSIPMessage, rmsg []byte, sipRes *sgsip.SGSIPMessage, skipauth *bool, smsg *string) int {
	if sgsip.SGSIPParseMessage(string(rmsg), sipRes) != sgsip.SGSIPRetOK {
		SIPExerPrintf(SIPExerLogError, "failed to parse sip response\n%+v\n\n", string(rmsg))
		return SIPExerErrSIPMessageFormat
	}
	if sipRes.FLine.MType != sgsip.FLineResponse {
		return SIPExerRetOK
	}

	if cliops.raw || cliops.noparse {
		// input not parsed -- no further processing
		return sipRes.FLine.Code
	}

	if sipRes.FLine.Code >= 100 && sipRes.FLine.Code <= 199 {
		return sipRes.FLine.Code
	}

	if (sipRes.FLine.Code == 401) || (sipRes.FLine.Code == 407) {
		if *skipauth {
			return sipRes.FLine.Code
		}
		if len(cliops.authapassword) == 0 {
			return sipRes.FLine.Code
		}
		var hbody string = ""
		if sipRes.FLine.Code == 401 {
			if sgsip.SGSIPMessageHeaderGet(sipRes, "WWW-Authenticate", &hbody) != sgsip.SGSIPRetOK {
				SIPExerPrintf(SIPExerLogError, "failed to get WWW-Authenticate\n")
				return SIPExerErrHeaderAuthGet
			}
		} else {
			if sgsip.SGSIPMessageHeaderGet(sipRes, "Proxy-Authenticate", &hbody) != sgsip.SGSIPRetOK {
				SIPExerPrintf(SIPExerLogError, "failed to get Proxy-Authenticate\n")
				return SIPExerErrHeaderAuthGet
			}
		}
		hparams := sgsip.SGSIPHeaderParseDigestAuthBody(hbody)
		if hparams == nil {
			SIPExerPrintf(SIPExerLogError, "failed to parse WWW/Proxy-Authenticate\n")
			return SIPExerErrHeaderAuthParse
		}
		s := strings.SplitN(*smsg, " ", 3)
		if len(s) != 3 {
			SIPExerPrintf(SIPExerLogError, "failed to get method and r-uri\n")
			return SIPExerErrSIPMessageFirstLine
		}

		hparams["method"] = s[0]
		hparams["uri"] = s[1]
		SIPExerPrintf(SIPExerLogDebug, "\nAuth params map:\n    %+v\n\n", hparams)
		authResponse := SIPExerBuildAuthResponseBody(cliops.authuser, cliops.authapassword, hparams)
		if len(authResponse) > 0 {
			SIPExerPrintf(SIPExerLogDebug, "authentication header body: [[%s]]\n", authResponse)
			if sipRes.FLine.Code == 401 {
				sgsip.SGSIPMessageHeaderSet(msgVal, "Authorization", authResponse)
			} else {
				sgsip.SGSIPMessageHeaderSet(msgVal, "Proxy-Authorization", authResponse)
			}
			sgsip.SGSIPMessageViaUpdate(msgVal)
			sgsip.SGSIPMessageCSeqUpdate(msgVal, 1)
			if sgsip.SGSIPMessageToString(msgVal, smsg) != sgsip.SGSIPRetOK {
				SIPExerPrintf(SIPExerLogError, "failed to rebuild sip message\n")
				return SIPExerErrSIPMessageToString
			}
			return sipRes.FLine.Code
		} else {
			SIPExerPrintf(SIPExerLogError, "failed to get authentication response header\n")
			return SIPExerErrSIPMessageResponse
		}
	}
	return sipRes.FLine.Code
}

func SIPExerSetWriteTimeoutValue(seDlg *SIPExerDialog, tVal int) {
	if seDlg.ProtoId == sgsip.ProtoUDP {
		seDlg.ConnUDP.Conn.SetWriteDeadline(time.Now().Add(time.Millisecond * time.Duration(tVal)))
	} else if seDlg.ProtoId == sgsip.ProtoTCP {
		seDlg.ConnTCP.Conn.SetWriteDeadline(time.Now().Add(time.Millisecond * time.Duration(tVal)))
	} else if seDlg.ProtoId == sgsip.ProtoTLS {
		seDlg.ConnTLS.Conn.SetWriteDeadline(time.Now().Add(time.Millisecond * time.Duration(tVal)))
	} else if seDlg.ProtoId == sgsip.ProtoWSS {
		seDlg.ConnWSS.Conn.SetWriteDeadline(time.Now().Add(time.Millisecond * time.Duration(tVal)))
	}
}

func SIPExerSetWriteTimeout(seDlg *SIPExerDialog) {
	SIPExerSetWriteTimeoutValue(seDlg, cliops.timeoutwrite)
}

func SIPExerSetReadTimeoutValue(seDlg *SIPExerDialog, tVal int) int {
	var err error
	if seDlg.ProtoId == sgsip.ProtoUDP {
		err = seDlg.ConnUDP.Conn.SetReadDeadline(time.Now().Add(time.Millisecond * time.Duration(tVal)))
		if err != nil {
			SIPExerPrintf(SIPExerLogError, "error: %v\n", err)
			return SIPExerErrUDPSetTimeout
		}
	} else if seDlg.ProtoId == sgsip.ProtoTCP {
		err = seDlg.ConnTCP.Conn.SetReadDeadline(time.Now().Add(time.Millisecond * time.Duration(tVal)))
		if err != nil {
			SIPExerPrintf(SIPExerLogError, "error: %v\n", err)
			return SIPExerErrTCPSetReadTimeout
		}
	} else if seDlg.ProtoId == sgsip.ProtoTLS {
		err = seDlg.ConnTLS.Conn.SetReadDeadline(time.Now().Add(time.Millisecond * time.Duration(tVal)))
		if err != nil {
			return SIPExerErrTLSSetReadTimeout
		}
	} else if seDlg.ProtoId == sgsip.ProtoWSS {
		err = seDlg.ConnWSS.Conn.SetReadDeadline(time.Now().Add(time.Millisecond * time.Duration(tVal)))
		if err != nil {
			return SIPExerErrWSSetReadTimeout
		}
	}
	return SIPExerRetOK
}

func SIPExerSetReadTimeout(seDlg *SIPExerDialog) int {
	if seDlg.ProtoId == sgsip.ProtoUDP {
		return SIPExerSetReadTimeoutValue(seDlg, seDlg.TimeoutStep)
	} else {
		return SIPExerSetReadTimeoutValue(seDlg, cliops.timeout)
	}
}

func SIPExerDialogReadBytes(seDlg *SIPExerDialog) int {
	var err error

	if seDlg.ProtoId == sgsip.ProtoUDP {
		var rcvAddr net.Addr
		seDlg.RecvN, rcvAddr, err = seDlg.ConnUDP.Conn.ReadFromUDP(seDlg.RecvBuf)
		if err != nil {
			SIPExerPrintf(SIPExerLogDebug, "not receiving after %dms (bytes %d - %v)\n", seDlg.TimeoutVal, seDlg.RecvN, err)
			if cliops.connectudp {
				if strings.Contains(err.Error(), "recvfrom: connection refused") {
					SIPExerPrintf(SIPExerLogError, "stop receiving - ICMP error\n")
					return SIPExerErrUDPICMPTimeout
				}
			}
			return SIPExerErrUDPReceiveTimeout
		} else {
			seDlg.RecvAddr = rcvAddr.String()
		}
	} else if seDlg.ProtoId == sgsip.ProtoTCP {
		seDlg.RecvN, err = seDlg.ConnTCP.Conn.Read(seDlg.RecvBuf)
		if err != nil {
			SIPExerPrintf(SIPExerLogError, "not receiving after %dms (bytes %d - %v)\n", cliops.timeout, seDlg.RecvN, err)
			return SIPExerErrTCPRead
		}
	} else if seDlg.ProtoId == sgsip.ProtoTLS {
		seDlg.RecvN, err = seDlg.ConnTLS.Conn.Read(seDlg.RecvBuf)
		if err != nil {
			SIPExerPrintf(SIPExerLogError, "not receiving after %dms (bytes %d - %v)\n", cliops.timeout, seDlg.RecvN, err)
			return SIPExerErrTLSRead
		}
	} else if seDlg.ProtoId == sgsip.ProtoWSS {
		seDlg.RecvN, err = seDlg.ConnWSS.Conn.Read(seDlg.RecvBuf)
		if err != nil {
			SIPExerPrintf(SIPExerLogError, "not receiving after %dms (bytes %d - %v)\n", cliops.timeout, seDlg.RecvN, err)
			return SIPExerErrWSRead
		}
	}
	return SIPExerRetOK
}

func SIPExerSessionWaitAndRead(seDlg *SIPExerDialog) int {
	var smsg string = ""
	tStart := time.Now()
	tWait := cliops.sessionwait
	for {
		SIPExerPrintf(SIPExerLogInfo, "waiting for %d milliseconds\n", tWait)

		ret := SIPExerSetReadTimeoutValue(seDlg, tWait)
		if ret < 0 {
			return ret
		}
		seDlg.RecvBuf = make([]byte, cliops.buffersize)
		ret = SIPExerDialogReadBytes(seDlg)
		tNow := time.Now()
		if tNow.UnixMilli()-tStart.UnixMilli() >= int64(tWait) {
			break
		}
		if ret == SIPExerRetOK && seDlg.RecvN > 0 {
			SIPExerPrintf(SIPExerLogInfo, "packet-received: from=%s bytes=%d data=[[---", seDlg.RecvAddr, seDlg.RecvN)
			SIPExerMessagePrint("\n", string(seDlg.RecvBuf), "\n")
			SIPExerPrintf(SIPExerLogInfo, "---]]\n")
			if len(seDlg.RecvBuf) > 16 {
				sipRcv := sgsip.SGSIPMessage{}
				if sgsip.SGSIPParseMessage(string(seDlg.RecvBuf), &sipRcv) != sgsip.SGSIPRetOK {
					SIPExerPrintf(SIPExerLogError, "failed to parse sip message\n%+v\n\n", string(seDlg.RecvBuf))
					return SIPExerErrSIPMessageFormat
				}
				if sipRcv.FLine.MType == sgsip.FLineRequest {
					if sipRcv.FLine.MethodId == sgsip.SIPMethodINVITE {
						if sgsip.SGSIPMessageToResponseString(&sipRcv, "480", "Temporarily Unavailable", &smsg) != sgsip.SGSIPRetOK {
							SIPExerPrintf(SIPExerLogError, "failed to build sip response\n")
							return SIPExerErrSIPMessageToString
						}
					} else {
						if sgsip.SGSIPMessageToResponseString(&sipRcv, "200", "OK Now", &smsg) != sgsip.SGSIPRetOK {
							SIPExerPrintf(SIPExerLogError, "failed to build sip response\n")
							return SIPExerErrSIPMessageToString
						}
					}
					if sipRcv.FLine.MethodId == sgsip.SIPMethodBYE && seDlg.State < SIPExerDialogTerminated {
						seDlg.State = SIPExerDialogTerminated
					}
					SIPExerSetWriteTimeoutValue(seDlg, 1000)
					SIPExerPrintf(SIPExerLogInfo, "sending to %s %s: [[---", seDlg.Proto, seDlg.TargetAddr)
					SIPExerMessagePrint("\n", smsg, "\n")
					SIPExerPrintf(SIPExerLogInfo, "---]]\n\n")
					SIPExerSendBytes(seDlg, []byte(smsg))
				}
			}
		}
		tWait = int(tStart.UnixMilli() + int64(cliops.sessionwait) - tNow.UnixMilli())
	}
	return SIPExerRetOK
}

func SIPExerSendBytes(seDlg *SIPExerDialog, bmsg []byte) int {
	var err error
	if seDlg.ProtoId == sgsip.ProtoUDP {
		if cliops.connectudp {
			_, err = seDlg.ConnUDP.Conn.Write(bmsg)
		} else {
			_, err = seDlg.ConnUDP.Conn.WriteToUDP(bmsg, seDlg.ConnUDP.DstAddr)
		}
		if err != nil {
			SIPExerPrintf(SIPExerLogError, "error writing on udp (connect: %v) - %v\n", cliops.connectudp, err)
			return SIPExerErrUDPWrite
		}
	} else if seDlg.ProtoId == sgsip.ProtoTCP {
		_, err = seDlg.ConnTCP.Conn.Write(bmsg)
		if err != nil {
			SIPExerPrintf(SIPExerLogError, "error writing on tcp - %v\n", err)
			return SIPExerErrTCPWrite
		}
	} else if seDlg.ProtoId == sgsip.ProtoTLS {
		_, err = seDlg.ConnTLS.Conn.Write(bmsg)
		if err != nil {
			SIPExerPrintf(SIPExerLogError, "error writing on tls - %v\n", err)
			return SIPExerErrTLSWrite
		}
	} else if seDlg.ProtoId == sgsip.ProtoWSS {
		_, err = seDlg.ConnWSS.Conn.Write(bmsg)
		if err != nil {
			SIPExerPrintf(SIPExerLogError, "error writing on wss - %v\n", err)
			return SIPExerErrWSWrite
		}
	} else {
		return SIPExerRetErr
	}
	return SIPExerRetOK
}

func SIPExerDialogLoop(tplstr string, tplfields map[string]interface{}, seDlg *SIPExerDialog) int {
	var smsg string = ""
	var err error
	var wmsg []byte

	if len(cliops.authuser) == 0 {
		cliops.authuser = fmt.Sprint(tplfields["fuser"])
	}

	seDlg.FirstRequest = new(sgsip.SGSIPMessage)
	ret := SIPExerPrepareMessage(tplstr, tplfields, seDlg.Proto, seDlg.LocalAddr, seDlg.TargetAddr, seDlg.FirstRequest)
	if ret != 0 {
		SIPExerPrintf(SIPExerLogError, "error preparing the message: %d\n", ret)
		return ret
	}
	smsg = seDlg.FirstRequest.Data
	SIPExerPrintf(SIPExerLogInfo, "local socket address: %v (%v)\n", seDlg.LocalAddr, seDlg.Proto)
	SIPExerPrintf(SIPExerLogInfo, "local via address: %v\n", tplfields["viaaddr"])
	SIPExerPrintf(SIPExerLogInfo, "sending to %s %s: [[---", seDlg.Proto, seDlg.TargetAddr)
	SIPExerMessagePrint("\n", smsg, "\n")
	SIPExerPrintf(SIPExerLogInfo, "---]]\n\n")

	wmsg = []byte(smsg)

	seDlg.RecvBuf = make([]byte, cliops.buffersize)
	// retransmissions loop
	for {
		if (seDlg.ProtoId != sgsip.ProtoUDP && seDlg.State != SIPExerDialogEarly) || seDlg.Resend {
			SIPExerSetWriteTimeout(seDlg)
			ret = SIPExerSendBytes(seDlg, wmsg)
			if ret < 0 {
				return ret
			}
			if seDlg.State == SIPExerDialogInit {
				seDlg.State = SIPExerDialogStarted
			}
		}

		seDlg.RecvN = 0
		ret = SIPExerSetReadTimeout(seDlg)
		if ret < 0 {
			return ret
		}
		ret = SIPExerDialogReadBytes(seDlg)
		if ret < 0 {
			if seDlg.ProtoId == sgsip.ProtoUDP && ret == SIPExerErrUDPReceiveTimeout {
				// perform udp retransmission
				if seDlg.TimeoutStep < cliops.timert2 {
					seDlg.TimeoutStep *= 2
				} else {
					seDlg.TimeoutStep = cliops.timert2
				}
				seDlg.TimeoutVal += seDlg.TimeoutStep
				if seDlg.TimeoutVal <= cliops.timeout {
					SIPExerPrintf(SIPExerLogInfo, "trying again - new timeout at %dms\n", seDlg.TimeoutVal)
					continue
				}
				SIPExerPrintf(SIPExerLogError, "error reading - bytes %d - %v\n", seDlg.RecvN, err)
				return SIPExerErrUDPReceiveTimeout
			} else {
				return ret
			}
		}

		if seDlg.RecvN > 0 {
			// absorb 1xx responses or deal with 401/407 auth challenges
			seDlg.LastResponse = new(sgsip.SGSIPMessage)
			ret = SIPExerProcessResponse(seDlg.FirstRequest, seDlg.RecvBuf, seDlg.LastResponse, &seDlg.SkipAuth, &smsg)
			if ret < 0 {
				return ret
			}
			SIPExerPrintf(SIPExerLogInfo, "response-received: from=%s bytes=%d data=[[---", seDlg.RecvAddr, seDlg.RecvN)
			SIPExerMessagePrint("\n", string(seDlg.RecvBuf), "\n")
			SIPExerPrintf(SIPExerLogInfo, "---]]\n")
			if ret/100 == 1 {
				// 1xx response - read again, but do not re-send UDP request
				if seDlg.ProtoId == sgsip.ProtoUDP {
					seDlg.Resend = false
				}
				if seDlg.State == SIPExerDialogStarted {
					seDlg.State = SIPExerDialogEarly
				}
				seDlg.RecvBuf = make([]byte, cliops.buffersize)
				continue
			}
			if ret/100 == 2 {
				if seDlg.State == SIPExerDialogEarly {
					seDlg.State = SIPExerDialogAnswered
				}
			}
			if ret/100 >= 3 {
				if seDlg.State <= SIPExerDialogEarly {
					seDlg.State = SIPExerDialogTerminated
				}
			}
			if seDlg.LastResponse.CSeq.MethodId == sgsip.SIPMethodINVITE {
				var sack string = ""
				ret1 := sgsip.SGSIPInviteToACKString(seDlg.FirstRequest, seDlg.LastResponse, &sack)
				if ret1 < 0 {
					return ret1
				}
				SIPExerPrintf(SIPExerLogInfo, "sending to %s %s: [[---", seDlg.Proto, seDlg.TargetAddr)
				SIPExerMessagePrint("\n", sack, "\n")
				SIPExerPrintf(SIPExerLogInfo, "---]]\n\n")
				if cliops.sessionwait > 0 && ret >= 200 && ret < 300 {
					// store 200-ack in dialog structure
					seDlg.AckRequest = new(sgsip.SGSIPMessage)
					if sgsip.SGSIPParseMessage(sack, seDlg.AckRequest) != sgsip.SGSIPRetOK {
						SIPExerPrintf(SIPExerLogError, "failed to parse ack message\n%+v\n\n", sack)
						return SIPExerErrSIPMessageFormat
					}
				}
				ret1 = SIPExerSendBytes(seDlg, []byte(sack))
				if ret1 < 0 {
					return ret
				}
				if ret/100 == 2 {
					if seDlg.State == SIPExerDialogAnswered {
						seDlg.State = SIPExerDialogConfirmed
					}
				}
				time.Sleep(200 * time.Millisecond)
			}
			if cliops.sessionwait > 0 && ret >= 200 && ret < 300 && (cliops.invite || cliops.register) {
				SIPExerSessionWaitAndRead(seDlg)
				smsg = ""
				cliops.sessionwait = 0
				if cliops.register {
					sgsip.SGSIPMessageViaUpdate(seDlg.FirstRequest)
					sgsip.SGSIPMessageCSeqUpdate(seDlg.FirstRequest, 1)
					sgsip.SGSIPMessageHeaderSet(seDlg.FirstRequest, "Expires", "0")
					if sgsip.SGSIPMessageToString(seDlg.FirstRequest, &smsg) != sgsip.SGSIPRetOK {
						SIPExerPrintf(SIPExerLogError, "failed to build sip unregister message\n")
						return SIPExerErrSIPMessageToString
					}
				} else {
					if seDlg.State == SIPExerDialogTerminated {
						// dialog terminated
						SIPExerPrintf(SIPExerLogInfo, "dialog terminated\n")
						return ret
					}
					if sgsip.SGSIPACKToByeString(seDlg.AckRequest, &smsg) != sgsip.SGSIPRetOK {
						SIPExerPrintf(SIPExerLogError, "failed to build sip bye message\n")
						return SIPExerErrSIPMessageToString
					}
				}
				if len(smsg) > 0 {
					// send the new message
					wmsg = []byte(smsg)
					SIPExerPrintf(SIPExerLogInfo, "sending to %s %s: [[---", seDlg.Proto, seDlg.TargetAddr)
					SIPExerMessagePrint("\n", smsg, "\n")
					SIPExerPrintf(SIPExerLogInfo, "---]]\n\n")
					if seDlg.ProtoId == sgsip.ProtoUDP {
						seDlg.TimeoutStep = cliops.timert1
						seDlg.TimeoutVal = seDlg.TimeoutStep
						seDlg.Resend = true
					}
					seDlg.SkipAuth = false
					seDlg.RecvBuf = make([]byte, cliops.buffersize)
					continue
				}
			}
			if ret >= 300 {
				if (ret == 401) || (ret == 407) {
					if seDlg.SkipAuth {
						return ret
					}
					if len(cliops.authapassword) == 0 {
						return ret
					}
					// authentication - send the new message
					wmsg = []byte(smsg)
					SIPExerPrintf(SIPExerLogInfo, "sending to %s %s: [[---", seDlg.Proto, seDlg.TargetAddr)
					SIPExerMessagePrint("\n", smsg, "\n")
					SIPExerPrintf(SIPExerLogInfo, "---]]\n\n")
					if seDlg.ProtoId == sgsip.ProtoUDP {
						seDlg.TimeoutStep = cliops.timert1
						seDlg.TimeoutVal = seDlg.TimeoutStep
						seDlg.Resend = true
					}
					seDlg.SkipAuth = true
					seDlg.RecvBuf = make([]byte, cliops.buffersize)
					seDlg.State = SIPExerDialogStarted
					continue
				}
			}
			return ret
		}
		break
	}

	SIPExerPrintf(SIPExerLogInfo, "packet-received: from=%s bytes=%d data=[[---", seDlg.RecvAddr, seDlg.RecvN)
	SIPExerMessagePrint("\n", string(seDlg.RecvBuf), "\n")
	SIPExerPrintf(SIPExerLogInfo, "---]]\n")
	return SIPExerRetOK
}

func SIPExerSendUDP(dstSockAddr sgsip.SGSIPSocketAddress, tplstr string, tplfields map[string]interface{}, tchan chan int) {
	var seDlg SIPExerDialog = SIPExerDialog{}
	var err error

	seDlg.Proto = "udp"
	seDlg.ProtoId = sgsip.ProtoUDP
	seDlg.AType = dstSockAddr.AType
	seDlg.ConnUDP = new(SIPExerConnUDP)

	strAFProto := "udp"
	if dstSockAddr.AType == sgsip.AFIPv4 {
		strAFProto = "udp4"
	} else if dstSockAddr.AType == sgsip.AFIPv6 {
		strAFProto = "udp6"
	} else {
		if cliops.af == sgsip.AFIPv4 {
			strAFProto = "udp4"
		} else if cliops.af == sgsip.AFIPv6 {
			strAFProto = "udp6"
		}
	}
	if len(cliops.laddr) > 0 {
		seDlg.ConnUDP.SrcAddr, err = net.ResolveUDPAddr(strAFProto, cliops.laddr)
		if err != nil {
			SIPExerPrintf(SIPExerLogError, "error: %v\n", err)
			tchan <- SIPExerErrResolveSrcUDPAddr
			return
		}
	}
	seDlg.ConnUDP.DstAddr, err = net.ResolveUDPAddr(strAFProto, dstSockAddr.Addr+":"+dstSockAddr.Port)
	if err != nil {
		SIPExerPrintf(SIPExerLogError, "error: %v\n", err)
		tchan <- SIPExerErrResolveDstUDPAddr
		return
	}
	if cliops.connectudp {
		seDlg.ConnUDP.Conn, err = net.DialUDP(strAFProto, seDlg.ConnUDP.SrcAddr, seDlg.ConnUDP.DstAddr)
	} else {
		seDlg.ConnUDP.Conn, err = net.ListenUDP(strAFProto, seDlg.ConnUDP.SrcAddr)
	}
	defer seDlg.ConnUDP.Conn.Close()
	if err != nil {
		SIPExerPrintf(SIPExerLogError, "error: %v\n", err)
		tchan <- SIPExerErrUDPSocket
		return
	}

	// get local address
	lAddr := seDlg.ConnUDP.Conn.LocalAddr().String()
	if strings.HasPrefix(lAddr, "0.0.0.0:") ||
		strings.HasPrefix(lAddr, "[::]:") {
		// try a connect-udp to learn local ip
		var conn1 *net.UDPConn
		conn1, err = net.DialUDP(strAFProto, nil, seDlg.ConnUDP.DstAddr)
		if err != nil {
			SIPExerPrintf(SIPExerLogError, "error: %v\n", err)
			tchan <- SIPExerErrUDPDial
			return
		}
		lAddr1 := conn1.LocalAddr().String()
		lIdx0 := strings.LastIndex(lAddr, ":")
		lIdx1 := strings.LastIndex(lAddr1, ":")
		lAddr = lAddr1[:lIdx1] + lAddr[lIdx0:]
		conn1.Close()
	}

	seDlg.LocalAddr = lAddr
	seDlg.TargetAddr = seDlg.ConnUDP.DstAddr.String()
	seDlg.RecvAddr = seDlg.TargetAddr
	seDlg.Resend = true
	seDlg.TimeoutStep = cliops.timert1
	seDlg.TimeoutVal = seDlg.TimeoutStep

	ret := SIPExerDialogLoop(tplstr, tplfields, &seDlg)
	tchan <- ret
}

func SIPExerSendTCP(dstSockAddr sgsip.SGSIPSocketAddress, tplstr string, tplfields map[string]interface{}, tchan chan int) {
	var seDlg SIPExerDialog = SIPExerDialog{}
	var err error

	seDlg.Proto = "tcp"
	seDlg.ProtoId = sgsip.ProtoTCP
	seDlg.AType = dstSockAddr.AType
	seDlg.ConnTCP = new(SIPExerConnTCP)

	strAFProto := "tcp"
	if dstSockAddr.AType == sgsip.AFIPv4 {
		strAFProto = "tcp4"
	} else if dstSockAddr.AType == sgsip.AFIPv6 {
		strAFProto = "tcp6"
	} else {
		if cliops.af == sgsip.AFIPv4 {
			strAFProto = "tcp4"
		} else if cliops.af == sgsip.AFIPv6 {
			strAFProto = "tcp6"
		}
	}
	if len(cliops.laddr) > 0 {
		seDlg.ConnTCP.SrcAddr, err = net.ResolveTCPAddr(strAFProto, cliops.laddr)
		if err != nil {
			SIPExerPrintf(SIPExerLogError, "error: %v\n", err)
			tchan <- SIPExerErrResolveSrcTCPAddr
			return
		}
	}
	seDlg.ConnTCP.DstAddr, err = net.ResolveTCPAddr(strAFProto, dstSockAddr.Addr+":"+dstSockAddr.Port)
	if err != nil {
		SIPExerPrintf(SIPExerLogError, "error: %v\n", err)
		tchan <- SIPExerErrResolveDstTCPAddr
		return
	}

	seDlg.ConnTCP.Conn, err = net.DialTCP(strAFProto, seDlg.ConnTCP.SrcAddr, seDlg.ConnTCP.DstAddr)

	if err != nil {
		SIPExerPrintf(SIPExerLogError, "error: %v\n", err)
		tchan <- SIPExerErrTCPDial
		return
	}

	defer seDlg.ConnTCP.Conn.Close()
	if err != nil {
		SIPExerPrintf(SIPExerLogError, "error: %v\n", err)
		tchan <- SIPExerErrTCPDial
		return
	}

	seDlg.LocalAddr = seDlg.ConnTCP.Conn.LocalAddr().String()
	seDlg.TargetAddr = seDlg.ConnTCP.Conn.RemoteAddr().String()
	seDlg.RecvAddr = seDlg.TargetAddr
	seDlg.TimeoutStep = cliops.timeout
	seDlg.TimeoutVal = seDlg.TimeoutStep

	ret := SIPExerDialogLoop(tplstr, tplfields, &seDlg)
	tchan <- ret
}

func SIPExerSendTLS(dstSockAddr sgsip.SGSIPSocketAddress, tplstr string, tplfields map[string]interface{}, tchan chan int) {
	var seDlg SIPExerDialog = SIPExerDialog{}
	var err error

	seDlg.Proto = "tls"
	seDlg.ProtoId = sgsip.ProtoTLS
	seDlg.AType = dstSockAddr.AType
	seDlg.ConnTLS = new(SIPExerConnTLS)

	strAFProto := "tcp"
	if dstSockAddr.AType == sgsip.AFIPv4 {
		strAFProto = "tcp4"
	} else if dstSockAddr.AType == sgsip.AFIPv6 {
		strAFProto = "tcp6"
	} else {
		if cliops.af == sgsip.AFIPv4 {
			strAFProto = "tcp4"
		} else if cliops.af == sgsip.AFIPv6 {
			strAFProto = "tcp6"
		}
	}
	var tlc tls.Config
	if len(cliops.tlscertificate) > 0 && len(cliops.tlskey) > 0 {
		var tlscert tls.Certificate
		tlscert, err = tls.LoadX509KeyPair(cliops.tlscertificate, cliops.tlskey)
		if err != nil {
			SIPExerPrintf(SIPExerLogError, "error: %v\n", err)
			tchan <- SIPExerErrTLSReadCertificates
			return
		}
		tlc = tls.Config{Certificates: []tls.Certificate{tlscert}, InsecureSkipVerify: false}
	} else {
		tlc = tls.Config{
			InsecureSkipVerify: false,
		}
	}
	if cliops.tlsinsecure {
		tlc.InsecureSkipVerify = true
	}

	seDlg.ConnTLS.Conn, err = tls.Dial(strAFProto, dstSockAddr.Addr+":"+dstSockAddr.Port, &tlc)
	if err != nil {
		SIPExerPrintf(SIPExerLogError, "error: %v\n", err)
		tchan <- SIPExerErrTLSDial
		return
	}
	defer seDlg.ConnTLS.Conn.Close()

	if cliops.verbosity >= SIPExerLogDebug {
		SIPExerPrintln(SIPExerLogDebug, "client: ", seDlg.ConnTLS.Conn.LocalAddr(), "connected to: ", seDlg.ConnTLS.Conn.RemoteAddr())
		state := seDlg.ConnTLS.Conn.ConnectionState()
		for _, v := range state.PeerCertificates {
			SIPExerPrintln(SIPExerLogDebug, fmt.Sprint(x509.MarshalPKIXPublicKey(v.PublicKey)))
			SIPExerPrintln(SIPExerLogDebug, v.Subject)
		}
		SIPExerPrintln(SIPExerLogDebug, "client: handshake: ", state.HandshakeComplete)
		SIPExerPrintln(SIPExerLogDebug, "client: mutual: ", state.NegotiatedProtocolIsMutual)
	}

	seDlg.LocalAddr = seDlg.ConnTLS.Conn.LocalAddr().String()
	seDlg.TargetAddr = seDlg.ConnTLS.Conn.RemoteAddr().String()
	seDlg.RecvAddr = seDlg.TargetAddr
	seDlg.TimeoutStep = cliops.timeout
	seDlg.TimeoutVal = seDlg.TimeoutStep

	ret := SIPExerDialogLoop(tplstr, tplfields, &seDlg)
	tchan <- ret
}

func SIPExerSendWSS(dstSockAddr sgsip.SGSIPSocketAddress, wsurlp *url.URL, tplstr string, tplfields map[string]interface{}, tchan chan int) {
	var seDlg SIPExerDialog = SIPExerDialog{}
	var err error
	var wsorgp *url.URL = nil

	seDlg.Proto = "wss"
	seDlg.ProtoId = sgsip.ProtoWSS
	seDlg.AType = dstSockAddr.AType
	seDlg.ConnWSS = new(SIPExerConnWSS)

	wsorgp, err = url.Parse(cliops.wsorigin)
	if err != nil {
		SIPExerPrintf(SIPExerLogError, "error: %v\n", err)
		tchan <- SIPExerErrWSOrigin
		return
	}

	var tlc tls.Config
	if len(cliops.tlscertificate) > 0 && len(cliops.tlskey) > 0 {
		var tlscert tls.Certificate
		tlscert, err = tls.LoadX509KeyPair(cliops.tlscertificate, cliops.tlskey)
		if err != nil {
			SIPExerPrintf(SIPExerLogError, "error: %v\n", err)
			tchan <- SIPExerErrTLSReadCertificates
			return
		}
		tlc = tls.Config{Certificates: []tls.Certificate{tlscert}, InsecureSkipVerify: false}
	} else {
		tlc = tls.Config{
			InsecureSkipVerify: false,
		}
	}
	if cliops.tlsinsecure {
		tlc.InsecureSkipVerify = true
	}

	// open ws connection
	// ws, err := websocket.Dial(wsurl, "", wsorigin)
	seDlg.ConnWSS.Conn, err = websocket.DialConfig(&websocket.Config{
		Location:  wsurlp,
		Origin:    wsorgp,
		Protocol:  []string{cliops.wsproto},
		Version:   13,
		TlsConfig: &tlc,
		Header:    http.Header{"User-Agent": {"sipexer v" + sipexerVersion}},
	})
	if err != nil {
		SIPExerPrintf(SIPExerLogError, "error: %v\n", err)
		tchan <- SIPExerErrWSDial
		return
	}
	defer seDlg.ConnWSS.Conn.Close()

	seDlg.LocalAddr = seDlg.ConnWSS.Conn.LocalAddr().String()
	seDlg.TargetAddr = seDlg.ConnWSS.Conn.RemoteAddr().String()
	seDlg.RecvAddr = seDlg.TargetAddr
	seDlg.TimeoutStep = cliops.timeout
	seDlg.TimeoutVal = seDlg.TimeoutStep

	ret := SIPExerDialogLoop(tplstr, tplfields, &seDlg)
	tchan <- ret
}

// SIPExerRandAlphaString - return random alphabetic string
func SIPExerRandAlphaString(olen int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

	b := make([]rune, olen)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// SIPExerRandAlphaNumString - return random alpha-numeric string
func SIPExerRandAlphaNumString(olen int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	b := make([]rune, olen)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// SIPExerRandNumString - return random numeric string
func SIPExerRandNumString(olen int) string {
	var letters = []rune("0123456789")

	b := make([]rune, olen)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// SIPExerRandHexString - return random hexa string
func SIPExerRandHexString(olen int) string {
	var letters = []rune("0123456789ABCDEF")

	b := make([]rune, olen)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// SIPExerBuildAuthResponseBody - return the body for auth header in response
func SIPExerBuildAuthResponseBody(username string, password string, hparams map[string]string) string {
	// https://en.wikipedia.org/wiki/Digest_access_authentication
	// HA1
	var HA1 string = ""
	h := md5.New()
	if cliops.ha1 {
		HA1 = password
	} else {
		A1 := fmt.Sprintf("%s:%s:%s", username, hparams["realm"], password)
		io.WriteString(h, A1)
		HA1 = fmt.Sprintf("%x", h.Sum(nil))
		// prepare for HA2
		h = md5.New()
	}

	// HA2
	A2 := fmt.Sprintf("%s:%s", hparams["method"], hparams["uri"])
	io.WriteString(h, A2)
	HA2 := fmt.Sprintf("%x", h.Sum(nil))

	var AuthHeader string
	if _, ok := hparams["qop"]; !ok {
		// build digest response
		response := SIPExerHMD5(strings.Join([]string{HA1, hparams["nonce"], HA2}, ":"))
		// build header body
		AuthHeader = fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", algorithm=MD5, response="%s"`,
			username, hparams["realm"], hparams["nonce"], hparams["uri"], response)
	} else {
		// build digest response
		cnonce := SIPExerRandomKey()
		response := SIPExerHMD5(strings.Join([]string{HA1, hparams["nonce"], "00000001", cnonce, hparams["qop"], HA2}, ":"))
		// build header body
		AuthHeader = fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", cnonce="%s", nc=00000001, qop=%s, opaque="%s", algorithm=MD5, response="%s"`,
			username, hparams["realm"], hparams["nonce"], hparams["uri"], cnonce, hparams["qop"], hparams["opaque"], response)
	}
	return AuthHeader
}

// SIPExerRandomKey - return random key (used for cnonce)
func SIPExerRandomKey() string {
	key := make([]byte, 12)
	for b := 0; b < len(key); {
		n, err := cryptorand.Read(key[b:])
		if err != nil {
			SIPExerPrintf(SIPExerLogError, "failed to get random bytes: %v\n", err)
			SIPExerExit(SIPExerErrRandomKey)
		}
		b += n
	}
	return base64.StdEncoding.EncodeToString(key)
}

// SIPExerHMD5 - return a lower-case hex MD5 digest of the parameter
func SIPExerHMD5(data string) string {
	md5d := md5.New()
	md5d.Write([]byte(data))
	return fmt.Sprintf("%x", md5d.Sum(nil))
}

func SIPExerMessagePrint(prefix string, smsg string, suffix string) {
	if !cliops.colormessage {
		fmt.Printf("%s%s%s", prefix, smsg, suffix)
		return
	}

	var msgObj sgsip.SGSIPMessage = sgsip.SGSIPMessage{}
	if sgsip.SGSIPParseMessage(smsg, &msgObj) != sgsip.SGSIPRetOK {
		fmt.Printf("%s%s%s%s%s", prefix, SIPExerLogLColorRed, smsg, SIPExerLogLColorReset, suffix)
		return
	}

	fmt.Printf("%s", prefix)
	if msgObj.FLine.MType == sgsip.FLineRequest {
		fmt.Printf("%s%s%s %s%s %s%s%s\r\n", SIPExerLogLColorBold, SIPExerLogLColorCyan,
			msgObj.FLine.Method, SIPExerLogLColorPurple, msgObj.FLine.URI,
			SIPExerLogLColorGreen, msgObj.FLine.Proto, SIPExerLogLColorReset)
	} else {
		fmt.Printf("%s%s%s %s%s %s%s%s\r\n", SIPExerLogLColorBold, SIPExerLogLColorCyan,
			msgObj.FLine.Proto, SIPExerLogLColorPurple, msgObj.FLine.CodeVal,
			SIPExerLogLColorGreen, msgObj.FLine.Reason, SIPExerLogLColorReset)
	}
	for _, h := range msgObj.Headers {
		fmt.Printf("%s: %s\r\n", h.Name, h.Body)
	}
	fmt.Printf("\r\n")

	if msgObj.Body.ContentLen > 0 {
		fmt.Printf("%s", msgObj.Body.Content)
	}
	fmt.Printf("%s", suffix)
}

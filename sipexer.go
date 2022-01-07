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
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/google/uuid"
	"github.com/miconda/sipexer/sgsip"
	"golang.org/x/net/websocket"
)

const sipexerVersion = "1.0.0"

var templateDefaultText string = `{{.method}} {{.ruri}} SIP/2.0
Via: SIP/2.0/{{.viaproto}} {{.viaaddr}}{{.rport}};branch=z9hG4bKSG.{{.viabranch}}
From: {{if .fname}}"{{.fname}}" {{end}}<sip:{{if .fuser}}{{.fuser}}@{{end}}{{.fdomain}}>;tag={{.fromtag}}
To: {{if .tname}}"{{.tname}}" {{end}}<sip:{{if .tuser}}{{.tuser}}@{{end}}{{.tdomain}}>
Call-ID: {{.callid}}
CSeq: {{.cseqnum}} {{.method}}
{{if .subject}}Subject: {{.subject}}{{else}}$rmeol{{end}}
{{if .date}}Date: {{.date}}{{else}}$rmeol{{end}}
{{if .contacturi}}Contact: {{.contacturi}}{{else}}$rmeol{{end}}
{{if .expires}}Expires: {{.expires}}{{else}}$rmeol{{end}}
{{if .useragent}}User-Agent: {{.useragent}}{{else}}$rmeol{{end}}
Content-Length: 0

`

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
	"date": "$daterfc1123"
}`

var templateFields = map[string]map[string]interface{}{
	"FIELDS:EMPTY": {},
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
var headerFields = make(paramFieldsType)

//
// CLIOptions - structure for command line options
type CLIOptions struct {
	method           string
	ruri             string
	body             string
	contenttype      string
	laddr            string
	useragent        string
	template         string
	templaterun      bool
	fields           string
	fieldseval       bool
	nocrlf           bool
	flagdefaults     bool
	templatedefaults bool
	timert1          int
	timert2          int
	timeout          int
	buffersize       int
	connectudp       bool
	af               int
	setdomains       bool
	tlsinsecure      bool
	tlscertificate   string
	tlskey           string
	wsorigin         string
	wsproto          string
	authuser         string
	authapassword    string
	noval            string
	version          bool
}

var cliops = CLIOptions{
	method:           "",
	ruri:             "",
	body:             "",
	contenttype:      "",
	laddr:            "",
	useragent:        "",
	template:         "",
	templaterun:      false,
	fields:           "",
	fieldseval:       false,
	nocrlf:           false,
	flagdefaults:     false,
	templatedefaults: false,
	timert1:          500,
	timert2:          4000,
	timeout:          32000,
	buffersize:       32 * 1024,
	connectudp:       false,
	af:               0,
	setdomains:       false,
	tlsinsecure:      false,
	tlscertificate:   "",
	tlskey:           "",
	wsorigin:         "http://127.0.0.1",
	wsproto:          "sip",
	authuser:         "",
	authapassword:    "",
	noval:            "no",
	version:          false,
}

//
// initialize application components
func init() {
	// command line arguments
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s (v%s):\n", filepath.Base(os.Args[0]), sipexerVersion)
		fmt.Fprintf(os.Stderr, "    (some options have short and long version)\n")
		flag.PrintDefaults()
		os.Exit(1)
	}
	flag.StringVar(&cliops.method, "method", cliops.method, "SIP method")
	flag.StringVar(&cliops.method, "mt", cliops.method, "SIP method")
	flag.StringVar(&cliops.ruri, "ruri", cliops.ruri, "request uri (r-uri)")
	flag.StringVar(&cliops.ruri, "ru", cliops.ruri, "request uri (r-uri)")
	flag.StringVar(&cliops.template, "template-file", cliops.template, "path to template file")
	flag.StringVar(&cliops.template, "tf", cliops.template, "path to template file")
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

	flag.BoolVar(&cliops.fieldseval, "fields-eval", cliops.fieldseval, "evaluate expression in fields file")
	flag.BoolVar(&cliops.fieldseval, "fe", cliops.fieldseval, "evaluate expression in fields file")
	flag.BoolVar(&cliops.nocrlf, "no-crlf", cliops.nocrlf, "do not replace '\\n' with '\\r\\n' inside the data to be sent (true|false)")
	flag.BoolVar(&cliops.flagdefaults, "flag-defaults", cliops.flagdefaults, "print flag (cli param) default values")
	flag.BoolVar(&cliops.flagdefaults, "fd", cliops.flagdefaults, "print flag (cli param) default values")
	flag.BoolVar(&cliops.templatedefaults, "template-defaults", cliops.templatedefaults, "print default (internal) template data")
	flag.BoolVar(&cliops.templatedefaults, "td", cliops.templatedefaults, "print default (internal) template data")
	flag.BoolVar(&cliops.templaterun, "template-run", cliops.templaterun, "run template execution and print the result")
	flag.BoolVar(&cliops.templaterun, "tr", cliops.templaterun, "run template execution and print the result")
	flag.BoolVar(&cliops.connectudp, "connect-udp", cliops.connectudp, "attempt first a connect for UDP (dial ICMP connect)")
	flag.BoolVar(&cliops.setdomains, "set-domains", cliops.setdomains, "set From/To domains based on R-URI")
	flag.BoolVar(&cliops.setdomains, "sd", cliops.setdomains, "set From/To domains based on R-URI")
	flag.BoolVar(&cliops.tlsinsecure, "tls-insecure", cliops.tlsinsecure, "skip tls certificate validation (true|false)")
	flag.BoolVar(&cliops.tlsinsecure, "ti", cliops.tlsinsecure, "skip tls certificate validation (true|false)")

	flag.IntVar(&cliops.timert1, "timer-t1", cliops.timert1, "value of t1 timer (milliseconds)")
	flag.IntVar(&cliops.timert2, "timer-t2", cliops.timert2, "value of t2 timer (milliseconds)")
	flag.IntVar(&cliops.timeout, "timeout", cliops.timeout, "timeout trying to send data (milliseconds)")
	flag.IntVar(&cliops.af, "af", cliops.af, "enforce address family for socket (4 or 6)")

	flag.Var(&paramFields, "field-val", "field value in format 'name:value' (can be provided many times)")
	flag.Var(&paramFields, "fv", "field value in format 'name:value' (can be provided many times)")

	flag.Var(&headerFields, "extra-header", "extra header in format 'name:body' (can be provided many times)")
	flag.Var(&headerFields, "xh", "extra header in format 'name:body' (can be provided many times)")

	flag.BoolVar(&cliops.version, "version", cliops.version, "print version")

	rand.Seed(time.Now().UnixNano())

}

//
// sipexer application
func main() {

	flag.Parse()

	fmt.Printf("\n")

	if cliops.version {
		fmt.Printf("%s v%s\n", filepath.Base(os.Args[0]), sipexerVersion)
		os.Exit(1)
	}

	if cliops.templatedefaults {
		fmt.Printf("Default template:\n\n")
		fmt.Println(templateDefaultText)
		fmt.Printf("Default fields:\n\n")
		fmt.Println(templateDefaultJSONFields)
		os.Exit(1)
	}
	if cliops.flagdefaults {
		flag.PrintDefaults()
		os.Exit(1)
	}
	// enable file name and line numbers in logging
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	var tplstr = ""
	if len(cliops.template) > 0 {
		tpldata, err1 := ioutil.ReadFile(cliops.template)
		if err1 != nil {
			log.Fatal(err1)
		}
		tplstr = string(tpldata)
	} else if len(templateDefaultText) > 0 {
		tplstr = templateDefaultText
	} else {
		log.Fatal("missing data template file ('-t' or '--template' parameter must be provided)")
	}
	var err error
	tplfields := make(map[string]interface{})
	if len(cliops.fields) > 0 {
		fieldsdata, err1 := ioutil.ReadFile(cliops.fields)
		if err1 != nil {
			log.Fatal(err1)
		}
		err = json.Unmarshal(fieldsdata, &tplfields)
		if err != nil {
			log.Fatal(err)
		}
	} else if len(templateDefaultJSONFields) > 0 {
		err = json.Unmarshal([]byte(templateDefaultJSONFields), &tplfields)
		if err != nil {
			log.Fatal(err)
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
				} else if tplfields[k] == "$cr" {
					tplfields[k] = "\r"
				} else if tplfields[k] == "$lf" {
					tplfields[k] = "\n"
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

	if len(cliops.method) > 0 {
		tplfields["method"] = strings.ToUpper(cliops.method)
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
					fmt.Fprintf(os.Stderr, "invalid websocket target: %v\n", dstAddr)
					os.Exit(-1)
				}
				if strings.HasPrefix(dstAddr, "wss://") {
					dstAddr = "wss:" + wsurlp.Host
				} else {
					dstAddr = "ws:" + wsurlp.Host
				}
			}
		} else if len(flag.Args()) == 2 {
			dstAddr = "upd:" + flag.Arg(0) + ":" + flag.Arg(1)
		} else if len(flag.Args()) == 3 {
			dstAddr = flag.Arg(0) + ":" + flag.Arg(1) + ":" + flag.Arg(2)
		} else {
			fmt.Fprintf(os.Stderr, "invalid number of arguments : %d\n", len(flag.Args()))
			os.Exit(-1)
		}
	}
	var dstSockAddr = sgsip.SGSIPSocketAddress{}
	var dstURI = sgsip.SGSIPURI{}
	if sgsip.SGSIPParseSocketAddress(dstAddr, &dstSockAddr) != sgsip.SGSIPRetOK {
		if sgsip.SGSIPParseURI(dstAddr, &dstURI) != sgsip.SGSIPRetOK {
			fmt.Fprintf(os.Stderr, "invalid destination address: %s\n", dstAddr)
			os.Exit(-1)
		} else {
			fmt.Printf("parsed SIP URI argument (%+v)\n", dstURI)
			sgsip.SGSIPURIToSocketAddress(&dstURI, &dstSockAddr)
		}
	} else {
		fmt.Printf("parsed socket address argument (%+v)\n", dstSockAddr)
		sgsip.SGSocketAddressToSIPURI(&dstSockAddr, 0, &dstURI)
	}
	var ok bool
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
			fmt.Fprintf(os.Stderr, "invalid ruri: %v\n", tplfields["ruri"])
			os.Exit(-1)
		}
		tplfields["fdomain"] = rURI.Addr
		tplfields["tdomain"] = rURI.Addr
	}
	if len(cliops.useragent) > 0 {
		if cliops.useragent != cliops.noval {
			tplfields["useragent"] = cliops.useragent
		}
	} else {
		tplfields["useragent"] = "SIPExer v" + sipexerVersion
	}
	var tret int
	if cliops.templaterun {
		_, ok = tplfields["viaaddr"]
		if !ok {
			if len(cliops.laddr) > 0 {
				tplfields["viaaddr"] = cliops.laddr
			} else {
				tplfields["viaaddr"] = "127.0.0.1:55060"
			}
		}
		_, ok = tplfields["viaproto"]
		if !ok {
			tplfields["viaproto"] = strings.ToUpper(dstSockAddr.Proto)
		}
		var msgVal sgsip.SGSIPMessage = sgsip.SGSIPMessage{}
		var smsg string = ""
		tret = SIPExerPrepareMessage(tplstr, tplfields, &msgVal)
		if tret != 0 {
			os.Exit(tret)
		}
		smsg = msgVal.Data
		msgVal = sgsip.SGSIPMessage{}
		if sgsip.SGSIPParseMessage(smsg, &msgVal) != sgsip.SGSIPRetOK {
			fmt.Fprintf(os.Stderr, "failed to parse sip message\n%+v\n\n", smsg)
			os.Exit(-1)
		}
		fmt.Printf("%+v\n\n", smsg)
		fmt.Printf("%+v\n\n", msgVal)

		os.Exit(1)
	}

	if (dstSockAddr.ProtoId != sgsip.ProtoUDP) && (dstSockAddr.ProtoId != sgsip.ProtoTCP) &&
		(dstSockAddr.ProtoId != sgsip.ProtoTLS) && (dstSockAddr.ProtoId != sgsip.ProtoWSS) {
		fmt.Fprintf(os.Stderr, "transport protocol not supported yet for target %s\n", dstAddr)
		os.Exit(-1)
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
	fmt.Printf("return code: %d\n\n", tret)
	os.Exit(tret)
}

func SIPExerPrepareMessage(tplstr string, tplfields map[string]interface{}, msgVal *sgsip.SGSIPMessage) int {
	var buf bytes.Buffer
	var tpl = template.Must(template.New("wsout").Parse(tplstr))
	var msgrebuild bool = false

	tpl.Execute(&buf, tplfields)

	var smsg string
	if cliops.nocrlf {
		smsg = strings.Replace(buf.String(), "$rmeol\n", "", -1)
	} else {
		smsg = strings.Replace(strings.Replace(buf.String(), "$rmeol\n", "", -1), "\n", "\r\n", -1)
	}

	if sgsip.SGSIPParseMessage(smsg, msgVal) != sgsip.SGSIPRetOK {
		fmt.Fprintf(os.Stderr, "failed to parse sip message\n%+v\n\n", smsg)
		return -200
	}

	if len(headerFields) > 0 {
		for hname, hbody := range headerFields {
			var hdrItem sgsip.SGSIPHeader = sgsip.SGSIPHeader{}
			hdrItem.Name = hname
			hdrItem.Body = hbody
			msgVal.Headers = append(msgVal.Headers, hdrItem)
		}
		msgrebuild = true
	}
	if len(cliops.body) > 0 {
		msgVal.Body.Content = cliops.body
		msgVal.Body.ContentLen = len(msgVal.Body.Content)
		if len(cliops.contenttype) > 0 {
			msgVal.Body.ContentType = cliops.contenttype
		} else {
			msgVal.Body.ContentType = "text/plain"
		}
		msgrebuild = true
	}
	if msgrebuild {
		if sgsip.SGSIPMessageToString(msgVal, &smsg) != sgsip.SGSIPRetOK {
			fmt.Fprintf(os.Stderr, "failed to rebuild sip message\n")
			return -201
		}
	}
	msgVal.Data = smsg
	return 0
}

func SIPExerProcessResponse(msgVal *sgsip.SGSIPMessage, rmsg []byte, sipRes *sgsip.SGSIPMessage, skipauth *bool, smsg *string) int {
	if sgsip.SGSIPParseMessage(string(rmsg), sipRes) != sgsip.SGSIPRetOK {
		fmt.Fprintf(os.Stderr, "failed to parse sip response\n%+v\n\n", string(rmsg))
		return -109
	}
	if sipRes.FLine.MType != sgsip.FLineResponse {
		return 0
	}

	if sipRes.FLine.Code >= 100 && sipRes.FLine.Code <= 199 {
		return sipRes.FLine.Code
	}
	if (sipRes.FLine.Code == 401) || (sipRes.FLine.Code == 407) {
		if *skipauth {
			return sipRes.FLine.Code
		}
		var hbody string = ""
		if sipRes.FLine.Code == 401 {
			if sgsip.SGSIPMessageHeaderGet(sipRes, "WWW-Authenticate", &hbody) != sgsip.SGSIPRetOK {
				fmt.Fprintf(os.Stderr, "failed to get WWW-Authenticate\n")
				return -109
			}
		} else {
			if sgsip.SGSIPMessageHeaderGet(sipRes, "Proxy-Authenticate", &hbody) != sgsip.SGSIPRetOK {
				fmt.Fprintf(os.Stderr, "failed to get Proxy-Authenticate\n")
				return -109
			}
		}
		hparams := sgsip.SGSIPHeaderParseDigestAuthBody(hbody)
		if hparams == nil {
			fmt.Fprintf(os.Stderr, "failed to parse WWW/Proxy-Authenticate\n")
			return -109
		}
		s := strings.SplitN(*smsg, " ", 3)
		if len(s) != 3 {
			fmt.Fprintf(os.Stderr, "failed to get method and r-uri\n")
			return -109
		}

		hparams["method"] = s[0]
		hparams["uri"] = s[1]
		fmt.Printf("\nAuth params map:\n    %+v\n\n", hparams)
		authResponse := SIPExerBuildAuthResponseBody(cliops.authuser, cliops.authapassword, hparams)
		if len(authResponse) > 0 {
			fmt.Printf("authentication header body: [[%s]]\n", authResponse)
			if sipRes.FLine.Code == 401 {
				sgsip.SGSIPMessageHeaderSet(msgVal, "Authorization", authResponse)
			} else {
				sgsip.SGSIPMessageHeaderSet(msgVal, "Proxy-Authorization", authResponse)
			}
			sgsip.SGSIPMessageCSeqUpdate(msgVal, 1)
			if sgsip.SGSIPMessageToString(msgVal, smsg) != sgsip.SGSIPRetOK {
				fmt.Fprintf(os.Stderr, "failed to rebuild sip message\n")
				return -109
			}
			return sipRes.FLine.Code
		} else {
			fmt.Fprintf(os.Stderr, "failed to get authentication response header\n")
			return -109
		}
	}
	return sipRes.FLine.Code
}

func SIPExerSendUDP(dstSockAddr sgsip.SGSIPSocketAddress, tplstr string, tplfields map[string]interface{}, tchan chan int) {
	var srcaddr *net.UDPAddr = nil
	var dstaddr *net.UDPAddr = nil
	var err error

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
		srcaddr, err = net.ResolveUDPAddr(strAFProto, cliops.laddr)
		if err != nil {
			tchan <- -100
			return
		}
	}
	dstaddr, err = net.ResolveUDPAddr(strAFProto, dstSockAddr.Addr+":"+dstSockAddr.Port)
	if err != nil {
		tchan <- -101
		return
	}
	var conn *net.UDPConn
	if cliops.connectudp {
		conn, err = net.DialUDP(strAFProto, srcaddr, dstaddr)
	} else {
		conn, err = net.ListenUDP(strAFProto, srcaddr)
	}
	defer conn.Close()
	if err != nil {
		tchan <- -103
		return
	}

	var ok bool
	_, ok = tplfields["viaaddr"]
	if !ok {
		lAddr0 := conn.LocalAddr().String()
		if strings.HasPrefix(lAddr0, "0.0.0.0:") ||
			strings.HasPrefix(lAddr0, "[::]:") {
			// try a connect-udp to learn local ip
			var conn1 *net.UDPConn
			conn1, err = net.DialUDP(strAFProto, nil, dstaddr)
			if err != nil {
				tchan <- -104
				return
			}
			lAddr1 := conn1.LocalAddr().String()
			lIdx0 := strings.LastIndex(lAddr0, ":")
			lIdx1 := strings.LastIndex(lAddr1, ":")
			tplfields["viaaddr"] = lAddr1[:lIdx1] + lAddr0[lIdx0:]
			conn1.Close()
		} else {
			tplfields["viaaddr"] = conn.LocalAddr().String()
		}
	}
	_, ok = tplfields["viaproto"]
	if !ok {
		tplfields["viaproto"] = "UDP"
	}

	fmt.Printf("local socket address: %v (%v)\n", conn.LocalAddr(), conn.LocalAddr().Network())
	fmt.Printf("local via address: %v\n", tplfields["viaaddr"])

	var msgVal sgsip.SGSIPMessage = sgsip.SGSIPMessage{}
	var smsg string = ""
	ret := SIPExerPrepareMessage(tplstr, tplfields, &msgVal)
	if ret != 0 {
		tchan <- ret
		return
	}
	smsg = msgVal.Data
	fmt.Printf("sending: [[\n%s]]\n\n", smsg)

	var wmsg []byte
	wmsg = []byte(smsg)

	timeoutStep := cliops.timert1
	timeoutVal := timeoutStep
	rmsg := make([]byte, cliops.buffersize)
	nRead := 0
	var rcvAddr net.Addr
	var resend bool = true
	var skipauth bool = false
	// retransmissions loop
	for {
		if resend {
			if cliops.connectudp {
				_, err = conn.Write(wmsg)
			} else {
				_, err = conn.WriteToUDP(wmsg, dstaddr)
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "error writing - %v\n", err)
				tchan <- -105
				return
			}
		}

		err = conn.SetReadDeadline(time.Now().Add(time.Millisecond * time.Duration(timeoutStep)))
		if err != nil {
			tchan <- -106
			return
		}
		nRead, rcvAddr, err = conn.ReadFromUDP(rmsg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "not receiving after %dms (bytes %d - %v)\n", timeoutVal, nRead, err)
			if cliops.connectudp {
				if strings.Contains(err.Error(), "recvfrom: connection refused") {
					fmt.Fprintf(os.Stderr, "stop receiving - ICMP error\n")
					tchan <- -107
					return
				}
			}
			if timeoutStep < cliops.timert2 {
				timeoutStep *= 2
			} else {
				timeoutStep = cliops.timert2
			}
			timeoutVal += timeoutStep
			if timeoutVal <= cliops.timeout {
				fmt.Fprintf(os.Stderr, "trying again - new timeout at %dms\n", timeoutVal)
				continue
			}
			fmt.Fprintf(os.Stderr, "error reading - bytes %d - %v\n", nRead, err)
			tchan <- -108
			return
		} else {
			if nRead > 0 {
				// absorb 1xx responses or deal with 401/407 auth challenges
				var sipRes sgsip.SGSIPMessage = sgsip.SGSIPMessage{}
				ret = SIPExerProcessResponse(&msgVal, rmsg, &sipRes, &skipauth, &smsg)
				if ret < 0 {
					tchan <- ret
					return
				}
				fmt.Printf("response-received: from=%s bytes=%d data=[[\n%s]]\n",
					rcvAddr.String(), nRead, string(rmsg))
				if ret/100 == 1 {
					// 1xx response - read again, but do not send request
					resend = false
					rmsg = make([]byte, cliops.buffersize)
					continue
				}
				if (ret == 401) || (ret == 407) {
					if skipauth {
						tchan <- ret
						return
					}
					// authentication - send the new message
					wmsg = []byte(smsg)
					fmt.Printf("sending: [[\n%s]]\n\n", smsg)
					timeoutStep = cliops.timert1
					timeoutVal = timeoutStep
					resend = true
					skipauth = true
					rmsg = make([]byte, cliops.buffersize)
					continue
				}
				tchan <- ret
				return
			}
		}
		break
	}

	fmt.Printf("packet-received: from=%s bytes=%d data=[[\n%s]]\n",
		rcvAddr.String(), nRead, string(rmsg))
	tchan <- 0
}

func SIPExerSendTCP(dstSockAddr sgsip.SGSIPSocketAddress, tplstr string, tplfields map[string]interface{}, tchan chan int) {
	var srcaddr *net.TCPAddr = nil
	var dstaddr *net.TCPAddr = nil
	var err error

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
		srcaddr, err = net.ResolveTCPAddr(strAFProto, cliops.laddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			tchan <- -100
			return
		}
	}
	dstaddr, err = net.ResolveTCPAddr(strAFProto, dstSockAddr.Addr+":"+dstSockAddr.Port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		tchan <- -101
		return
	}

	var conn *net.TCPConn
	conn, err = net.DialTCP(strAFProto, srcaddr, dstaddr)

	defer conn.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		tchan <- -103
		return
	}

	var ok bool
	_, ok = tplfields["viaaddr"]
	if !ok {
		tplfields["viaaddr"] = conn.LocalAddr().String()
	}
	_, ok = tplfields["viaproto"]
	if !ok {
		tplfields["viaproto"] = "TCP"
	}

	fmt.Printf("local socket address: %v (%v)\n", conn.LocalAddr(), conn.LocalAddr().Network())
	fmt.Printf("local via address: %v\n", tplfields["viaaddr"])

	var msgVal sgsip.SGSIPMessage = sgsip.SGSIPMessage{}
	var smsg string = ""
	ret := SIPExerPrepareMessage(tplstr, tplfields, &msgVal)
	if ret != 0 {
		tchan <- ret
		return
	}
	smsg = msgVal.Data
	fmt.Printf("sending: [[\n%s]]\n\n", smsg)

	var wmsg []byte
	wmsg = []byte(smsg)

	rmsg := make([]byte, cliops.buffersize)
	nRead := 0

	var skipauth bool = false
	for {
		err = conn.SetWriteDeadline(time.Now().Add(time.Millisecond * time.Duration(cliops.timeout)))
		_, err = conn.Write(wmsg)

		if err != nil {
			fmt.Fprintf(os.Stderr, "error writing - %v\n", err)
			tchan <- -105
			return
		}

		err = conn.SetReadDeadline(time.Now().Add(time.Millisecond * time.Duration(cliops.timeout)))
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			tchan <- -106
			return
		}
		nRead, err = conn.Read(rmsg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "not receiving after %dms (bytes %d - %v)\n", cliops.timeout, nRead, err)
			tchan <- -107
			return
		}
		if nRead > 0 {
			// absorb 1xx responses or deal with 401/407 auth challenges
			var sipRes sgsip.SGSIPMessage = sgsip.SGSIPMessage{}
			ret = SIPExerProcessResponse(&msgVal, rmsg, &sipRes, &skipauth, &smsg)
			if ret < 0 {
				tchan <- ret
				return
			}
			fmt.Printf("response-received: from=%s bytes=%d data=[[\n%s]]\n",
				dstaddr.String(), nRead, string(rmsg))
			if ret == 100 {
				// 1xx response - read again, but do not send request
				rmsg = make([]byte, cliops.buffersize)
				continue
			}
			if (ret == 401) || (ret == 407) {
				if skipauth {
					tchan <- ret
					return
				}
				// authentication - send the new message
				wmsg = []byte(smsg)
				fmt.Printf("sending: [[\n%s]]\n\n", smsg)
				skipauth = true
				rmsg = make([]byte, cliops.buffersize)
				continue
			}
			tchan <- ret
			return
		}
		break
	}
	fmt.Printf("packet-received: from=%s bytes=%d data=[[\n%s]]\n",
		dstaddr.String(), nRead, string(rmsg))
	tchan <- 0
}

func SIPExerSendTLS(dstSockAddr sgsip.SGSIPSocketAddress, tplstr string, tplfields map[string]interface{}, tchan chan int) {
	var err error

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
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			tchan <- -102
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
	var conn *tls.Conn

	conn, err = tls.Dial(strAFProto, dstSockAddr.Addr+":"+dstSockAddr.Port, &tlc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		tchan <- -103
		return
	}
	defer conn.Close()

	fmt.Println("client: ", conn.LocalAddr(), "connected to: ", conn.RemoteAddr())
	state := conn.ConnectionState()
	for _, v := range state.PeerCertificates {
		fmt.Println(x509.MarshalPKIXPublicKey(v.PublicKey))
		fmt.Println(v.Subject)
	}
	log.Println("client: handshake: ", state.HandshakeComplete)
	log.Println("client: mutual: ", state.NegotiatedProtocolIsMutual)

	var ok bool
	_, ok = tplfields["viaaddr"]
	if !ok {
		tplfields["viaaddr"] = conn.LocalAddr().String()
	}
	_, ok = tplfields["viaproto"]
	if !ok {
		tplfields["viaproto"] = "TLS"
	}

	fmt.Printf("local socket address: %v (%v)\n", conn.LocalAddr(), conn.LocalAddr().Network())
	fmt.Printf("local via address: %v\n", tplfields["viaaddr"])

	var msgVal sgsip.SGSIPMessage = sgsip.SGSIPMessage{}
	var smsg string = ""
	ret := SIPExerPrepareMessage(tplstr, tplfields, &msgVal)
	if ret != 0 {
		tchan <- ret
		return
	}
	smsg = msgVal.Data
	fmt.Printf("sending: [[\n%s]]\n\n", smsg)

	var wmsg []byte
	wmsg = []byte(smsg)

	rmsg := make([]byte, cliops.buffersize)
	nRead := 0

	var skipauth bool = false
	for {
		err = conn.SetWriteDeadline(time.Now().Add(time.Millisecond * time.Duration(cliops.timeout)))
		_, err = conn.Write(wmsg)

		if err != nil {
			fmt.Fprintf(os.Stderr, "error writing - %v\n", err)
			tchan <- -105
			return
		}
		err = conn.SetReadDeadline(time.Now().Add(time.Millisecond * time.Duration(cliops.timeout)))
		if err != nil {
			tchan <- -106
			return
		}
		nRead, err = conn.Read(rmsg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "not receiving after %dms (bytes %d - %v)\n", cliops.timeout, nRead, err)
			tchan <- -107
			return
		}
		if nRead > 0 {
			// absorb 1xx responses or deal with 401/407 auth challenges
			var sipRes sgsip.SGSIPMessage = sgsip.SGSIPMessage{}
			ret = SIPExerProcessResponse(&msgVal, rmsg, &sipRes, &skipauth, &smsg)
			if ret < 0 {
				tchan <- ret
				return
			}
			fmt.Printf("response-received: from=%s bytes=%d data=[[\n%s]]\n",
				conn.RemoteAddr().String(), nRead, string(rmsg))
			if ret == 100 {
				// 1xx response - read again, but do not send request
				rmsg = make([]byte, cliops.buffersize)
				continue
			}
			if (ret == 401) || (ret == 407) {
				if skipauth {
					tchan <- ret
					return
				}
				// authentication - send the new message
				wmsg = []byte(smsg)
				fmt.Printf("sending: [[\n%s]]\n\n", smsg)
				skipauth = true
				rmsg = make([]byte, cliops.buffersize)
				continue
			}
			tchan <- ret
			return
		}
		break
	}
	fmt.Printf("packet-received: from=%s bytes=%d data=[[\n%s]]\n",
		conn.RemoteAddr().String(), nRead, string(rmsg))
	tchan <- 0
}

func SIPExerRandAlphaString(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func SIPExerSendWSS(dstSockAddr sgsip.SGSIPSocketAddress, wsurlp *url.URL, tplstr string, tplfields map[string]interface{}, tchan chan int) {
	var err error
	var wsorgp *url.URL = nil

	wsorgp, err = url.Parse(cliops.wsorigin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		tchan <- -100
		return
	}

	var tlc tls.Config
	if len(cliops.tlscertificate) > 0 && len(cliops.tlskey) > 0 {
		var tlscert tls.Certificate
		tlscert, err = tls.LoadX509KeyPair(cliops.tlscertificate, cliops.tlskey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			tchan <- -102
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
	var ws *websocket.Conn = nil
	ws, err = websocket.DialConfig(&websocket.Config{
		Location:  wsurlp,
		Origin:    wsorgp,
		Protocol:  []string{cliops.wsproto},
		Version:   13,
		TlsConfig: &tlc,
		Header:    http.Header{"User-Agent": {"sipexer v" + sipexerVersion}},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		tchan <- -103
		return
	}

	var ok bool
	_, ok = tplfields["viaaddr"]
	if !ok {
		tplfields["viaaddr"] = SIPExerRandAlphaString(10) + ".invalid"
	}
	_, ok = tplfields["viaproto"]
	if !ok {
		tplfields["viaproto"] = "WSS"
	}

	fmt.Printf("local socket address: %v (%v)\n", ws.LocalAddr(), ws.LocalAddr().Network())
	fmt.Printf("local via address: %v\n", tplfields["viaaddr"])

	var msgVal sgsip.SGSIPMessage = sgsip.SGSIPMessage{}
	var smsg string = ""
	ret := SIPExerPrepareMessage(tplstr, tplfields, &msgVal)
	if ret != 0 {
		tchan <- ret
		return
	}
	smsg = msgVal.Data
	fmt.Printf("sending: [[\n%s]]\n\n", smsg)

	var wmsg []byte
	wmsg = []byte(smsg)

	rmsg := make([]byte, cliops.buffersize)
	nRead := 0

	err = ws.SetWriteDeadline(time.Now().Add(time.Millisecond * time.Duration(cliops.timeout)))
	_, err = ws.Write(wmsg)

	if err != nil {
		fmt.Fprintf(os.Stderr, "error writing - %v\n", err)
		tchan <- -105
		return
	}
	err = ws.SetReadDeadline(time.Now().Add(time.Millisecond * time.Duration(cliops.timeout)))
	if err != nil {
		tchan <- -106
		return
	}
	nRead, err = ws.Read(rmsg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "not receiving after %dms (bytes %d - %v)\n", cliops.timeout, nRead, err)
		tchan <- -107
		return
	}
	fmt.Printf("packet-received: from=%s bytes=%d data=[[\n%s]]\n",
		ws.RemoteAddr().String(), nRead, string(rmsg))
	tchan <- 0
}

//
// BuildAuthResponseBody - return the body for auth header in response
func SIPExerBuildAuthResponseBody(username string, password string, hparams map[string]string) string {
	// https://en.wikipedia.org/wiki/Digest_access_authentication
	// HA1
	h := md5.New()
	A1 := fmt.Sprintf("%s:%s:%s", username, hparams["realm"], password)
	io.WriteString(h, A1)
	HA1 := fmt.Sprintf("%x", h.Sum(nil))

	// HA2
	h = md5.New()
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

//
// SIPExerRandomKey - return random key (used for cnonce)
func SIPExerRandomKey() string {
	key := make([]byte, 12)
	for b := 0; b < len(key); {
		n, err := cryptorand.Read(key[b:])
		if err != nil {
			panic("failed to get random bytes")
		}
		b += n
	}
	return base64.StdEncoding.EncodeToString(key)
}

//
// SIPExerHMD5 - return a lower-case hex MD5 digest of the parameter
func SIPExerHMD5(data string) string {
	md5d := md5.New()
	md5d.Write([]byte(data))
	return fmt.Sprintf("%x", md5d.Sum(nil))
}

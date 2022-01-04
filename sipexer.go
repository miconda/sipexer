/**
 * SIP (RFC3261) Command Line Tool
 * (C) Copyright 2021-2022 Daniel-Constantin Mierla (asipto.com)
 * License: GPLv3
 */

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	mathrand "math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/google/uuid"
	"github.com/miconda/sipexer/sgsip"
)

const sipexerVersion = "1.0.0"

var templateDefaultText string = `{{.method}} {{.ruri}} SIP/2.0
Via: SIP/2.0/{{.viaproto}} {{.viaaddr}}{{.rport}};branch=z9hG4bKSG.{{.viabranch}}
From: "{{.caller}}" <sip:{{.caller}}@{{.domain}}>;tag={{.fromtag}}
To: "{{.callee}}" <sip:{{.callee}}@{{.domain}}>
Call-ID: {{.callid}}
CSeq: {{.cseqnum}} {{.method}}
{{if .subject}}Subject: {{.subject}}{{else}}$rmeol{{end}}
Date: {{.date}}
{{if .contacturi}}Contact: {{.contacturi}}{{else}}$rmeol{{end}}
{{if .expires}}Expires: {{.expires}}{{else}}$rmeol{{end}}
{{if .useragent}}User-Agent: {{.useragent}}{{else}}$rmeol{{end}}
Content-Length: 0

`

var templateDefaultJSONFields string = `{
	"method": "OPTIONS",
	"caller": "alice",
	"callee": "bob",
	"domain": "localhost",
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
	ruri             string
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
	version          bool
}

var cliops = CLIOptions{
	ruri:             "",
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
	flag.StringVar(&cliops.ruri, "ruri", cliops.ruri, "request uri (r-uri)")
	flag.StringVar(&cliops.template, "template-file", cliops.template, "path to template file")
	flag.StringVar(&cliops.template, "tf", cliops.template, "path to template file")
	flag.StringVar(&cliops.fields, "fields-file", cliops.fields, "path to the json fields file")
	flag.StringVar(&cliops.fields, "ff", cliops.fields, "path to the json fields file")
	flag.StringVar(&cliops.laddr, "laddr", cliops.laddr, "local address (`ip:port` or `:port`)")
	flag.StringVar(&cliops.useragent, "user-agent", cliops.useragent, "user agent value")
	flag.StringVar(&cliops.useragent, "ua", cliops.useragent, "user agent value")

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

	flag.IntVar(&cliops.timert1, "timer-t1", cliops.timert1, "value of t1 timer (milliseconds)")
	flag.IntVar(&cliops.timert2, "timer-t2", cliops.timert2, "value of t2 timer (milliseconds)")
	flag.IntVar(&cliops.timeout, "timeout", cliops.timeout, "timeout trying to send data (milliseconds)")
	flag.IntVar(&cliops.af, "af", cliops.af, "enforce address family for socket (4 or 6)")

	flag.Var(&paramFields, "field-val", "field value in format 'name:value' (can be provided many times)")
	flag.Var(&paramFields, "fv", "field value in format 'name:value' (can be provided many times)")

	flag.Var(&headerFields, "extra-header", "extra header in format 'name:body' (can be provided many times)")
	flag.Var(&headerFields, "xh", "extra header in format 'name:body' (can be provided many times)")

	flag.BoolVar(&cliops.version, "version", cliops.version, "print version")
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
		fmt.Println("Default template:\n")
		fmt.Println(templateDefaultText)
		fmt.Println("Default fields:\n")
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
					mathrand.Seed(time.Now().Unix())
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
				if strings.Trim(paramFields[k], " \t\r\n") == "no" {
					tplfields[k] = ""
				}
			} else {
				tplfields[k] = paramFields[k]
			}
		}
	}

	dstAddr := "udp:127.0.0.1:5060"
	if len(flag.Args()) > 0 {
		if len(flag.Args()) == 1 {
			dstAddr = flag.Arg(0)
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
	if len(cliops.useragent) > 0 {
		if cliops.useragent != "no" {
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
		var smsg string = ""
		tret = SIPExerPrepareMessage(tplstr, tplfields, &smsg)
		if tret != 0 {
			os.Exit(tret)
		}
		var msgVal sgsip.SGSIPMessage = sgsip.SGSIPMessage{}
		if sgsip.SGSIPParseMessage(smsg, &msgVal) != sgsip.SGSIPRetOK {
			fmt.Fprintf(os.Stderr, "failed to parse sip message\n%+v\n\n", smsg)
			os.Exit(-1)
		}
		fmt.Printf("%+v\n\n", smsg)
		fmt.Printf("%+v\n\n", msgVal)

		os.Exit(1)
	}

	if dstSockAddr.ProtoId != sgsip.ProtoUDP {
		fmt.Fprintf(os.Stderr, "transport protocol not supported yet for target %s\n", dstAddr)
		os.Exit(-1)
	}

	tchan := make(chan int, 1)
	go SIPExerSendUDP(dstSockAddr, tplstr, tplfields, tchan)
	tret = <-tchan
	close(tchan)
	fmt.Printf("return code: %d\n\n", tret)
	os.Exit(tret)
}

func SIPExerPrepareMessage(tplstr string, tplfields map[string]interface{}, outstr *string) int {
	var buf bytes.Buffer
	var tpl = template.Must(template.New("wsout").Parse(tplstr))
	tpl.Execute(&buf, tplfields)

	var smsg string
	if cliops.nocrlf {
		smsg = strings.Replace(buf.String(), "$rmeol\n", "", -1)
	} else {
		smsg = strings.Replace(strings.Replace(buf.String(), "$rmeol\n", "", -1), "\n", "\r\n", -1)
	}

	var msgVal sgsip.SGSIPMessage = sgsip.SGSIPMessage{}
	if sgsip.SGSIPParseMessage(smsg, &msgVal) != sgsip.SGSIPRetOK {
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

		if sgsip.SGSIPMessageToString(&msgVal, &smsg) != sgsip.SGSIPRetOK {
			fmt.Fprintf(os.Stderr, "failed to rebuild sip message\n")
			return -201
		}
	}
	*outstr = smsg
	return 0
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

	var smsg string = ""
	ret := SIPExerPrepareMessage(tplstr, tplfields, &smsg)
	if ret != 0 {
		tchan <- ret
		return
	}
	fmt.Printf("sending: [[\n%s]]\n\n", smsg)

	var wmsg []byte
	wmsg = []byte(smsg)

	timeoutStep := cliops.timert1
	timeoutVal := timeoutStep
	rmsg := make([]byte, cliops.buffersize)
	nRead := 0
	var rcvAddr net.Addr

	// retransmissions loop
	for {
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
		}
		break
	}

	fmt.Printf("packet-received: from=%s bytes=%d data=[[\n%s]]\n",
		rcvAddr.String(), nRead, string(rmsg))
	tchan <- 0
}

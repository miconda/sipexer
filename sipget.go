/**
 * WebSocket Command Line Tool
 * (C) Copyright 2021 Daniel-Constantin Mierla (asipto.com)
 * License: GPLv3
 */

package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/miconda/sipget/sgsip"
)

const sipgetVersion = "1.0.0"

var templateDefaultText string = `{{.method}} sip:{{.callee}}@{{.domain}} SIP/2.0
Via: SIP/2.0/WSS df7jal23ls0d.invalid;branch=z9hG4bKasudf-3696-24845-1
From: "{{.caller}}" <sip:{{.caller}}@{{.domain}}>;tag={{.fromtag}}
To: "{{.callee}}" <sip:{{.callee}}@{{.domain}}>
Call-ID: {{.callid}}
CSeq: {{.cseqnum}} {{.method}}
Subject: testing
Date: {{.date}}
Content-Length: 0

`

var templateDefaultJSONFields string = `{
	"method": "OPTIONS",
	"caller": "alice",
	"callee": "bob",
	"domain": "localhost",
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

//
// CLIOptions - structure for command line options
type CLIOptions struct {
	ruri    string
	version bool
}

var cliops = CLIOptions{
	ruri:    "sip:127.0.0.1:5060",
	version: false,
}

//
// initialize application components
func init() {
	// command line arguments
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s (v%s):\n", filepath.Base(os.Args[0]), sipgetVersion)
		fmt.Fprintf(os.Stderr, "    (some options have short and long version)\n")
		flag.PrintDefaults()
		os.Exit(1)
	}
	flag.StringVar(&cliops.ruri, "ruri", cliops.ruri, "request uri (r-uri)")
	flag.BoolVar(&cliops.version, "version", cliops.version, "print version")
}

//
// sipget application
func main() {

	flag.Parse()

	fmt.Printf("\n")

	if cliops.version {
		fmt.Printf("%s v%s\n", filepath.Base(os.Args[0]), sipgetVersion)
		os.Exit(1)
	}

	var sockAddr = sgsip.SGSIPSocketAddress{}
	sgsip.SGSIPParseSocketAddress("udp:127.0.0.1:5060", &sockAddr)
	fmt.Printf("%+v\n", sockAddr)
	sockAddr = sgsip.SGSIPSocketAddress{}
	sgsip.SGSIPParseSocketAddress("tls:[::1]:5061", &sockAddr)
	fmt.Printf("%+v\n", sockAddr)
	sockAddr = sgsip.SGSIPSocketAddress{}
	sgsip.SGSIPParseSocketAddress("tcp:localhost1:5080", &sockAddr)
	fmt.Printf("%+v\n", sockAddr)
	sockAddr = sgsip.SGSIPSocketAddress{}
	sgsip.SGSIPParseSocketAddress("[::1]:5060", &sockAddr)
	fmt.Printf("%+v\n", sockAddr)
	sockAddr = sgsip.SGSIPSocketAddress{}
	sgsip.SGSIPParseSocketAddress("127.0.0.1", &sockAddr)
	fmt.Printf("%+v\n", sockAddr)
	fmt.Printf("\n")

	var sipURI = sgsip.SGSIPURI{}
	sgsip.SGSIPParseURI("sip:127.0.0.1:5090", &sipURI)
	fmt.Printf("%+v\n", sipURI)
	sipURI = sgsip.SGSIPURI{}
	sgsip.SGSIPParseURI("sip:alice@127.0.0.1:5060", &sipURI)
	fmt.Printf("%+v\n", sipURI)
	sipURI = sgsip.SGSIPURI{}
	sgsip.SGSIPParseURI("sip:127.0.0.1:5080", &sipURI)
	fmt.Printf("%+v\n", sipURI)
	sipURI = sgsip.SGSIPURI{}
	sgsip.SGSIPParseURI("sip:127.0.0.1:5061;transport=tls", &sipURI)
	fmt.Printf("%+v\n", sipURI)
	sipURI = sgsip.SGSIPURI{}
	sgsip.SGSIPParseURI("sip:127.0.0.1:5061;transport=tls;line=55", &sipURI)
	fmt.Printf("%+v\n", sipURI)
	sipURI = sgsip.SGSIPURI{}
	sgsip.SGSIPParseURI("sip:[::1]:5061;line=44;transport=tls", &sipURI)
	fmt.Printf("%+v\n", sipURI)
	sipURI = sgsip.SGSIPURI{}
	sgsip.SGSIPParseURI("sip:bob;user=sip@127.0.0.1:5060", &sipURI)
	fmt.Printf("%+v\n", sipURI)

	var paramVal = sgsip.SGSIPParam{}
	sgsip.SGSIPParamsGet("line=44;transport=tls", "line", 0, &paramVal)
	fmt.Printf("param val: %+v\n", paramVal)
	paramVal = sgsip.SGSIPParam{}
	sgsip.SGSIPParamsGet("line=\"44\";transport=tls", "line", 1, &paramVal)
	fmt.Printf("param val: %+v\n", paramVal)

	var flineVal = sgsip.SGSIPFirstLine{}
	sgsip.SGSIPParseFirstLine("SIP/2.0 200 All OK\r\n", &flineVal)
	fmt.Printf("%+v\n", flineVal)
	flineVal = sgsip.SGSIPFirstLine{}
	sgsip.SGSIPParseFirstLine("INVITE sip:alice@server.com SIP/2.0\r\n", &flineVal)
	fmt.Printf("%+v\n", flineVal)
}

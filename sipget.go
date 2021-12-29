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

	dstAddr := "udp:127.0.0.1:5060"
	if len(flag.Args()) > 0 {
		if len(flag.Args()) == 1 {
			dstAddr = flag.Arg(0)
		} else if len(flag.Args()) == 2 {
			dstAddr = "upd:" + flag.Arg(0) + flag.Arg(0)
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
		}
	} else {
		fmt.Printf("parsed socket address argument (%+v)\n", dstSockAddr)
	}
	os.Exit(0)
}

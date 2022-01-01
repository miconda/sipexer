/**
 * WebSocket Command Line Tool
 * (C) Copyright 2021 Daniel-Constantin Mierla (asipto.com)
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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/google/uuid"
	"github.com/miconda/sipget/sgsip"
)

const sipgetVersion = "1.0.0"

var templateDefaultText string = `{{.method}} sip:{{.callee}}@{{.domain}} SIP/2.0
Via: SIP/2.0/{{.viaproto}} {{.viaaddr}};rport;branch=z9hG4bKSG.{{.viabranch}}
From: "{{.caller}}" <sip:{{.caller}}@{{.domain}}>;tag={{.fromtag}}
To: "{{.callee}}" <sip:{{.callee}}@{{.domain}}>
Call-ID: {{.callid}}
CSeq: {{.cseqnum}} {{.method}}
{{if .subject}}Subject: {{.subject}}{{else}}$rmeol{{end}}
Date: {{.date}}
{{if .contacturi}}Contact: {{.contacturi}}{{else}}$rmeol{{end}}
{{if .expires}}Contact: {{.expires}}{{else}}$rmeol{{end}}
Content-Length: {{if .contentlength}}{{.contentlength}}{{else}}0{{end}}

`

var templateDefaultJSONFields string = `{
	"method": "OPTIONS",
	"caller": "alice",
	"callee": "bob",
	"domain": "localhost",
	"viabranch": "$uuid",
	"viaproto": "UDP",
	"viaaddr": "127.0.0.1:15060",
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
	ruri             string
	laddr            string
	template         string
	templaterun      bool
	fields           string
	fieldseval       bool
	crlf             bool
	flagdefaults     bool
	templatedefaults bool
	version          bool
}

var cliops = CLIOptions{
	ruri:             "sip:127.0.0.1:5060",
	laddr:            "",
	template:         "",
	templaterun:      false,
	fields:           "",
	fieldseval:       false,
	crlf:             false,
	flagdefaults:     false,
	templatedefaults: false,
	version:          false,
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
	flag.StringVar(&cliops.template, "template", cliops.template, "path to template file")
	flag.StringVar(&cliops.template, "t", cliops.template, "path to template file")
	flag.StringVar(&cliops.fields, "fields", cliops.fields, "path to the json fields file")
	flag.StringVar(&cliops.fields, "f", cliops.fields, "path to the json fields file")
	flag.StringVar(&cliops.laddr, "laddr", cliops.laddr, "local address (`ip:port` or `:port`)")
	flag.BoolVar(&cliops.fieldseval, "fields-eval", cliops.fieldseval, "evaluate expression in fields file")
	flag.BoolVar(&cliops.crlf, "crlf", cliops.crlf, "replace '\\n' with '\\r\\n' inside the data to be sent (true|false)")
	flag.BoolVar(&cliops.flagdefaults, "flag-defaults", cliops.flagdefaults, "print flag (cli param) default values")
	flag.BoolVar(&cliops.templatedefaults, "template-defaults", cliops.templatedefaults, "print default (internal) template data")
	flag.BoolVar(&cliops.templaterun, "template-run", cliops.templaterun, "run template execution and print the result")

	flag.Var(&paramFields, "field-val", "field value in format 'name:value' (can be provided many times)")

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

	// buffer to send over SIP link
	var buf bytes.Buffer
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
			tplfields[k] = paramFields[k]
		}
	}
	var tpl = template.Must(template.New("wsout").Parse(tplstr))
	tpl.Execute(&buf, tplfields)

	var wmsg []byte
	if cliops.crlf {
		wmsg = []byte(strings.Replace(strings.Replace(buf.String(), "$rmeol\n", "", -1), "\n", "\r\n", -1))
	} else {
		wmsg = []byte(strings.Replace(buf.String(), "$rmeol\n", "", -1))
	}

	if cliops.templaterun {
		fmt.Println(string(wmsg))
		os.Exit(1)
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
	}
	os.Exit(0)
}

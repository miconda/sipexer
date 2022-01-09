# sipexer #

Modern and flexible SIP ([RFC3261](https://datatracker.ietf.org/doc/html/rfc3261)) command line tool.

## Overview ##

`sipexer` is a cli tool that facilitates sending SIP requests to servers. It uses a flexible template
system to allow defining many parts of the SIP request via command line parameters. It has support
for UDP, TCP, TLS and WebSocket transport protocols, being suitable to test modern WebRTC SIP servers.

`sipexer` is not a SIP cli softphone, but a tool for crafting SIP requests mainly for the purpose
of testing SIP signaling routing or monitoring servers.

It is written in Go, aiming to be usable from Linux, MacOS or Windows.

The meaning of the name `sipexer`: randomly selected to be easy to write and pronounce,
quickly after thought of it as the shortening of `SIP EXEcutoR`.

## Installation ##

## Install ##

### Compile From Sources ###

First install [Go](http://golang.org). Once the Go environment is configured, clone `sipexer` git repository:

```
git clone https://github.com/miconda/sipexer
```

Download dependencies and build:

```
cd sipexer
go get ./...
go build .
```

The binary `sipexer` should be generated in the current directory.

### Download Binary Release ###

TBA

## Usage ##

Prototype:

```
sipexer [options] [target]
```
See `sipexer -h` for the command line options and arguments.

Defaults:
  * target address: `sip:127.0.0.1:5060`
  * SIP method: `OPTIONS`
  * From user: `alice`
  * From domain: `localhost`
  * To user: `bob`
  * To domain: `localhost`

### Examples ###

Send an `OPTIONS` request over `UDP` to `127.0.0.1` and port `5060` - couple of variants:

```
sipexer
sipexer 127.0.0.1
sipexer 127.0.0.1 5060
sipexer udp 127.0.0.1 5060
sipexer udp:127.0.0.1:5060
sipexer sip:127.0.0.1:5060
sipexer "sip:127.0.0.1:5060;transport=udp"
```

Specify a different R-URI:

```
sipexer -ruri sip:alice@server.com udp:127.0.0.1:5060
```

Send from UDP local port 55060:

```
sipexer -laddr 127.0.0.1:55060 udp:127.0.0.1:5060
```

Send `REGISTER` request with generated contact, expires as well as user and password authentication:

```
sipexer -register -cb -ex 600 -au alice -ap test123 udp:127.0.0.1:5060
```

Set `fuser` field to `carol`:

```
sipexer -sd -fv "fuser:carol" udp:127.0.0.1:5060
```

Set `fuser` field to `carol` and `tuser` field to `david`:

```
sipexer -sd -fv "fuser:carol"  -fv "tuser:david" udp:127.0.0.1:5060
```

Add extra headers:

```
sipexer -sd -xh "X-My-Key:abcdefgh" -xh "P-Info:xyzw" udp:127.0.0.1:5060
```

Send `MESSAGE` request with body:

```
sipexer -message -mb 'Hello!' -sd -su udp:127.0.0.1:5060
```

## Message Template ##

### Template Data ###

The message to be sent via the SIP connection is built from a template file and a fields file.

The template file can contain any any of the directives supported by Go package `text/template` - for more see:

  * https://golang.org/pkg/text/template/

Example:

```
{{.method}} {{.ruri}} SIP/2.0
Via: SIP/2.0/{{.viaproto}} {{.viaaddr}}{{.rport}};branch=z9hG4bKSG.{{.viabranch}}
From: {{if .fname}}"{{.fname}}" {{end}}<sip:{{if .fuser}}{{.fuser}}@{{end}}{{.fdomain}}>;tag={{.fromtag}}
To: {{if .tname}}"{{.tname}}" {{end}}<sip:{{if .tuser}}{{.tuser}}@{{end}}{{.tdomain}}>
Call-ID: {{.callid}}
CSeq: {{.cseqnum}} {{.method}}
{{if .subject}}Subject: {{.subject}}{{else}}$rmeol{{end}}
{{if .date}}Date: {{.date}}{{else}}$rmeol{{end}}
{{if .contacturi}}Contact: {{.contacturi}}{{if .contactparams}};{{.contactparams}}{{end}}{{else}}$rmeol{{end}}
{{if .expires}}Expires: {{.expires}}{{else}}$rmeol{{end}}
{{if .useragent}}User-Agent: {{.useragent}}{{else}}$rmeol{{end}}
Content-Length: 0

```

The internal template can be found at the top of `sipexer.go` file.

### Template Fields ###

The fields file has to contain a JSON document with the fields to be replaced
in the template file. The path to the JSON file is provided via `-ff` or `--fields-file`
parameters.

When the `--fields-eval` of `-fe` cli option is provided, `sipexer` evaluates the values of the
fields in the root structure of the JSON document. That means special tokens (expressions)
are replaced if the value of the field is a string matching one of the next:

  * `"$uuid"` - replace with a UUID value
  * `"$randseq"` - replace with a random number from `1` to `1 000 000`.
  * `"$datefull"` - replace with output of `time.Now().String()`
  * `"$daterfc1123"` - replace with output of `time.Now().Format(time.RFC1123)`
  * `"$dateansic"` - replace with output of `time.Now().Format(time.ANSIC)`
  * `"$dateunix"` - replace with output of `time.Now().Format(time.UnixDate)`
  * `"$timestamp"` - replace with output of `time.Now().Unix()`
  * `"$cr"` - replace with `\r`
  * `"$lf"` - replace with `\n`

When internal template is used, `--fields-eval` is turned on.

Example fields file:

```json
{
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
}
```

The internal fields data can be found at the top of `sipexer.go` file.

The values for fields can be also provided using `--field-val` or `-fv` cli parameter, in
format `name:value`, for example:

```
sipexer --field-val="domain:openrcs.com" ...
```

The value provided via `--field-val` overwrites the value provided in the
JSON fields file.

When sending out, before the template is evaluated, the following fields are also
added internally and will replace the corresponding `{{.name}}` in the template:

  * `proto` - lower(`proto`)
  * `protoup` - upper(`proto`)
  * `localaddr` - local address - `ip:port`
  * `localip` - local ip
  * `localport` - local port
  * `targetaddr` - remote address - `ip:port`
  * `targetip` - remote ip
  * `targetport` - remote port
  * `cr` - `\r`
  * `lf` - `\n`
  * `tab` - `\t`


## Alternatives ##

There are several alternatives that might be useful to consider:

  * `sipp` - SIP testing tool using XML-based scenarios
  * `sipsak` - SIP swiss army knife - SIP cli testing tool
  * `wsctl` - WebSocket cli tool with basic support for SIP
  * `baresip` - cli SIP softphone
  * `pjsua` - cli SIP softphone

## License ##

`GPLv3`

Copyright: `Daniel-Constantin Mierla` ([Asipto](https://www.asipto.com))

## Contributions ##

Contributions are welcome!

Fork and do pull requests:

  * https://github.com/miconda/sipexer
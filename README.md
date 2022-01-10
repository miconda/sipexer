# sipexer #

Modern and flexible SIP ([RFC3261](https://datatracker.ietf.org/doc/html/rfc3261)) command line tool.

Project URL: https://github.com/miconda/sipexer

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

Binary releases for `Linux`, `MacOS` and `Windows` are available at:

  * https://github.com/miconda/sipexer/releases

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

```shell
sipexer -sd -fu "carol" udp:127.0.0.1:5060
# or 
sipexer -sd -fv "fuser:carol" udp:127.0.0.1:5060
```

Set `fuser` field to `carol` and `tuser` field to `david`, with
R-URI user same as To-user when providing proxy address destination:

```shell
sipexer -sd -fu "carol"  -tu "david" -su udp:127.0.0.1:5060
# or
sipexer -sd -fv "fuser:carol"  -fv "tuser:david" -su udp:127.0.0.1:5060
```

Add extra headers:

```
sipexer -sd -xh "X-My-Key:abcdefgh" -xh "P-Info:xyzw" udp:127.0.0.1:5060
```

Send `MESSAGE` request with body:

```
sipexer -message -mb 'Hello!' -sd -su udp:127.0.0.1:5060
```

Send `MESSAGE` request with body over `tcp`:

```
sipexer -message -mb 'Hello!' -sd -su tcp:127.0.0.1:5060
```

Send `MESSAGE` request with body over `tls`:

```
sipexer -message -mb 'Hello!' -sd -su tls:127.0.0.1:5061
```

Send `MESSAGE` request with body over `wss` (WebSocket Secure):

```
sipexer -message -mb 'Hello!' -sd -su wss://server.com:8443/sip
```

### Target Address ###

The target address can be provided as last arguments to the `sipexer` command. It is
options, if not provided, then the SIP message is sent over `UDP` to `127.0.0.1` port `5060`.

The format can be:

  * SIP URI (e.g., `sip:user@server.com:5080;transport=tls`)
  * SIP proxy socket address in format `proto:host:port` (e.g., `tls:server.com:5061`)
  * WSS URL (e.g., `wss://server.com:8442/webrtc`)
  * only the server `hostname` or `IP` (e.g., `server.com`)
  * `host:port` (transport protocol is set to `UDP`)
  * `proto:host` (port is set to `5060`)
  * `host port` (transport protocol is set to `UDP`)
  * `proto host` (port is set to `5060`)
  * `proto host port` (same as `proto:host:port`)


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

  * `"$cr"` - replace with `\r`
  * `"$dateansic"` - replace with output of `time.Now().Format(time.ANSIC)`
  * `"$datefull"` - replace with output of `time.Now().String()`
  * `"$daterfc1123"` - replace with output of `time.Now().Format(time.RFC1123)`
  * `"$dateunix"` - replace with output of `time.Now().Format(time.UnixDate)`
  * `"$randseq"` - replace with a random number from `1` to `1 000 000`
  * `"$rand(max)"` - replace with a random number from `0` to `max`
  * `"$rand(min,max)"` - replace with a random number from `min` to `max`
  * `"$rmeol"` - remove next end of line character `\n`
  * `"$timestamp"` - replace with output of `time.Now().Unix()`
  * `"$lf"` - replace with `\n`
  * `"$uuid"` - replace with a UUID value

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
added internally and will replace the corresponding `{{.name}}` (e.g., `{{.proto}}`)
in the template:

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
// logging functions
package main

import (
	"fmt"
	"path/filepath"
	"runtime"
)

// return and error code values
const (
	SIPExerLogNone  = 0
	SIPExerLogError = 1
	SIPExerLogInfo  = 2
	SIPExerLogDebug = 3
)

func SIPExerLogPrefix(level int) string {
	if level == SIPExerLogError {
		return "error"
	} else if level == SIPExerLogInfo {
		return "info"
	} else if level == SIPExerLogDebug {
		return "debug"
	} else {
		return "none"
	}
}

func SIPExerPrintf(level int, format string, v ...interface{}) {
	if cliops.verbosity < level {
		return
	}
	pc, filename, line, _ := runtime.Caller(1)
	logmsg := fmt.Sprintf(format, v...)
	fmt.Printf("[%s] [%s:%d] %s(): %s", SIPExerLogPrefix(level), filepath.Base(filename),
		line, runtime.FuncForPC(pc).Name(), logmsg)
}

func SIPExerPrintln(level int, v ...interface{}) {
	if cliops.verbosity < level {
		return
	}
	pc, filename, line, _ := runtime.Caller(1)
	logmsg := fmt.Sprintln(v...)
	fmt.Printf("[%s] [%s:%d] %s(): %s", SIPExerLogPrefix(level), filepath.Base(filename),
		line, runtime.FuncForPC(pc).Name(), logmsg)
}

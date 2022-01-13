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

// return and error code values
const (
	SIPExerLogLColorReset = "\033[0m"

	SIPExerLogLColorRed    = "\033[31m"
	SIPExerLogLColorGreen  = "\033[32m"
	SIPExerLogLColorYellow = "\033[33m"
	SIPExerLogLColorBlue   = "\033[34m"
	SIPExerLogLColorPurple = "\033[35m"
	SIPExerLogLColorCyan   = "\033[36m"
	SIPExerLogLColorWhite  = "\033[37m"

	SIPExerLogLColorBold      = "\033[1m"
	SIPExerLogLColorBoldReset = "\033[22m"
	SIPExerLogLColorUnderline = "\033[4m"
	SIPExerLogLColorReversed  = "\033[7m"
)

func SIPExerLogPrefix(level int) string {
	boldSet := ""
	boldReset := ""
	if cliops.coloroutput {
		boldSet = SIPExerLogLColorBold
		boldReset = SIPExerLogLColorBoldReset
	}
	if level == SIPExerLogError {
		return boldSet + "error" + boldReset
	} else if level == SIPExerLogInfo {
		return boldSet + "info" + boldReset
	} else if level == SIPExerLogDebug {
		return boldSet + "debug" + boldReset
	} else {
		return boldSet + "none" + boldReset
	}
}

func SIPExerLogColorSet(level int) string {
	if !cliops.coloroutput {
		return ""
	}
	if level == SIPExerLogError {
		return SIPExerLogLColorRed
	} else if level == SIPExerLogInfo {
		return SIPExerLogLColorCyan
	} else if level == SIPExerLogDebug {
		return ""
	} else {
		return SIPExerLogLColorGreen
	}
}

func SIPExerLogColorReset(level int) string {
	if !cliops.coloroutput {
		return ""
	}
	if level == SIPExerLogDebug {
		return ""
	}
	return SIPExerLogLColorReset
}

func SIPExerPrintf(level int, format string, v ...interface{}) {
	if cliops.verbosity < level {
		return
	}
	pc, filename, line, _ := runtime.Caller(1)
	logmsg := fmt.Sprintf(format, v...)
	fmt.Printf("%s[%s] [%s:%d] %s(): %s%s", SIPExerLogColorSet(level),
		SIPExerLogPrefix(level),
		filepath.Base(filename), line, runtime.FuncForPC(pc).Name(),
		logmsg,
		SIPExerLogColorReset(level))
}

func SIPExerPrintln(level int, v ...interface{}) {
	if cliops.verbosity < level {
		return
	}
	pc, filename, line, _ := runtime.Caller(1)
	logmsg := fmt.Sprintln(v...)
	fmt.Printf("%s[%s] [%s:%d] %s(): %s%s", SIPExerLogColorSet(level),
		SIPExerLogPrefix(level),
		filepath.Base(filename), line, runtime.FuncForPC(pc).Name(),
		logmsg,
		SIPExerLogColorReset(level))
}

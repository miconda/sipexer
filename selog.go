// logging functions
package main

import (
	"fmt"
	"path/filepath"
	"runtime"
)

func SIPExerPrintf(level int, format string, v ...interface{}) {
	if cliops.verbosity < level {
		return
	}
	pc, filename, line, _ := runtime.Caller(1)
	logmsg := fmt.Sprintf(format, v...)
	fmt.Printf("[info] [%s:%d] %s(): %s", filepath.Base(filename), line, runtime.FuncForPC(pc).Name(), logmsg)
}

func SIPExerPrintln(level int, v ...interface{}) {
	if cliops.verbosity < level {
		return
	}
	pc, filename, line, _ := runtime.Caller(1)
	logmsg := fmt.Sprintln(v...)
	fmt.Printf("[info] [%s:%d] %s(): %s", filepath.Base(filename), line, runtime.FuncForPC(pc).Name(), logmsg)
}

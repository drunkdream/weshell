package main

import (
	"flag"
	"fmt"
)

var debugMode = flag.Bool("debug", false, "enable debug logging")

func logInfo(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
}

func logDebug(format string, args ...interface{}) {
	if debugMode != nil && *debugMode {
		fmt.Printf(format+"\n", args...)
	}
}

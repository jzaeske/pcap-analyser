// Package log provides an extension to write default log to a log file, which may be specified via command line
// argument -logFile. Import this module for its side effect with
// import _ log
package log

import (
	"log"
	"flag"
	"io"
	"os"
)

var file string

func init() {
	flag.StringVar(&file, "logFile", "", "File to write additional logs")
	if file != "" {
		if file, err := os.Create(file); err != nil {
			multiWriter := io.MultiWriter(os.Stdout, file)
			log.SetOutput(multiWriter)
			return
		}
	}
	log.Println("No log File specified. Writing additional logs to stdout only.")
}
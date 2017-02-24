package report

import (
	"log"
	"flag"
	"io"
	"os"
)

var logFile string

func init() {
	flag.StringVar(&logFile, "logFile", "", "File to write additional logs")
	if file, err := os.Create(logFile); err != nil {
		multiwriter := io.MultiWriter(os.Stderr, file)
		log.SetOutput(multiwriter)
	} else {
		log.SetOutput(os.Stderr)
		log.Println("No log File specified. Writing additional logs to stderr only.")
	}
}
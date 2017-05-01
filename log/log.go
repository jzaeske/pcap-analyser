package log

import (
	"io"
	"log"
	"os"
)

func SetLogFile(file string) {
	if file != "" {
		if file, err := os.Create(file); err == nil {
			multiWriter := io.MultiWriter(os.Stdout, file)
			log.SetOutput(multiWriter)
			return
		}
	}
	log.Println("No log File specified. Writing additional logs to stdout only.")
}

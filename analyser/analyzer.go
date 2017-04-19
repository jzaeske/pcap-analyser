package analyser

import (
	"./components"
	"./report"
	"./stuff"
	"encoding/csv"
	"log"
	"os"
	"time"
)

type Analyzer struct {
	pcaps       []string
	workerCount int
	workers     []components.FileWorker
}

func NewAnalyzer(pcaps []string, concurrentFiles int) (a *Analyzer) {
	a = &Analyzer{}
	a.pcaps = pcaps
	a.workerCount = concurrentFiles
	return
}

func (a *Analyzer) Run() {

	start := time.Now()

	var files = make(chan string)

	for i := 0; i < a.workerCount; i++ {
		chain, wg := stuff.GenerateExampleComposer()
		var worker = components.NewFileWorker(i, chain)
		a.workers = append(a.workers, worker)
		go worker.Run(files, wg)
	}

	for _, file := range a.pcaps {
		files <- file
	}
	close(files)

	components.WaitForFileWorkers()

	elapsed := time.Since(start)

	log.Printf("Took %s\n", elapsed)

}

func (a *Analyzer) ExportCsv(outputDir string) {
	log.Println("Writing report")

	if err := os.MkdirAll(outputDir, 0777); err != nil {
		log.Println("Unable to access Director; Using .")
		outputDir = "."
	}

	for _, reportFile := range report.GetIdentifiers() {
		if f, err := os.Create(outputDir + "/" + reportFile + ".csv"); err == nil {
			w := csv.NewWriter(f)

			result := report.GetJoinedAccumulator(reportFile)

			for line := range result.GetCsv() {
				if err := w.Write(line); err != nil {
					log.Fatalln("error writing record to csv:", err)
				}
			}

			// Write any buffered data to the underlying writer (standard output).
			w.Flush()

			if err := w.Error(); err != nil {
				log.Fatal(err)
			}
		} else {
			log.Println(err)
		}
	}
}

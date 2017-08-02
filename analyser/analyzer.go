package analyser

import (
	logger "../log"
	"../util"
	"./components"
	"./report"
	"encoding/csv"
	"log"
	"os"
	"time"
	"strings"
	"path/filepath"
)

type Analyzer struct {
	config  *AnalysisConfig
	workers []components.FileWorker
}

func NewAnalyzer(config *AnalysisConfig) (a *Analyzer) {
	a = &Analyzer{}
	a.config = config
	components.OutputDir = config.Settings.Output
	return
}

func (a *Analyzer) Run() {

	start := time.Now()

	a.initOutput()

	var files = make(chan string)

	for i := 0; i < a.config.Settings.Concurrent; i++ {
		chain, wg := a.config.GetChain()
		var worker = components.NewFileWorker(i, chain, &a.config.SpecialPackets, a.config.Settings.BufferSize)
		a.workers = append(a.workers, worker)
		go worker.Run(files, wg)
	}

	if pcaps, err := a.config.GetInputFiles(); err == nil {
		for _, file := range pcaps {
			files <- file
		}
	} else {
		log.Fatalln(err)
	}
	close(files)

	components.WaitForFileWorkers()

	elapsed := time.Since(start)

	log.Printf("Took %s\n", elapsed)

}

func (a *Analyzer) initOutput() {
	outputDir := a.config.Settings.Output

	if err := os.MkdirAll(outputDir, 0777); err != nil {
		log.Println("Unable to access Director; Using .")
		outputDir = "."
	}

	util.CopyFile(a.config.ConfigFile, outputDir+"/input.xml")

	logger.SetLogFile(outputDir + "/" + a.config.Settings.LogFile)
}

func (a *Analyzer) ExportCsv() {
	outputDir := a.config.Settings.Output
	log.Println("Writing report")

	if err := os.MkdirAll(outputDir, 0777); err != nil {
		log.Println("Unable to access Director; Using .")
		outputDir = "."
	}

	for _, reportFile := range report.GetIdentifiers() {
		outputFile := outputDir + "/" + reportFile + ".csv"
		if err := os.MkdirAll(filepath.Dir(outputFile), 0777); err != nil {
			log.Println("Unable to create custom dir; Using default")
			outputFile = outputDir + "/" + strings.Replace(reportFile, "/", "_", -1) + ".csv"
		}
		if f, err := os.Create(outputFile); err == nil {
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
			f.Close()
		} else {
			log.Println(err)
		}
	}
}

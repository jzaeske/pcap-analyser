package analyser

import (
	"./parser"
	"./report"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

type Analyzer struct {
	pcaps       []string
	workerCount int
}

func NewAnalyzer(pcaps []string, concurrentFiles int) (a Analyzer) {
	a.pcaps = pcaps
	a.workerCount = concurrentFiles
	return
}

func (a Analyzer) Run(output string) {

	start := time.Now()

	var files = make(chan string)
	var wg = sync.WaitGroup{}
	var acc = report.NewAccumulator(1000)

	for i := 0; i < a.workerCount; i++ {
		worker := parser.NewPcap(fmt.Sprintf("Worker %d", i), files)
		acc.AddWorker(&worker)
		wg.Add(1)
		go worker.Run(&wg)
	}

	go acc.Run()

	for _, file := range a.pcaps {
		files <- file
	}
	close(files)

	fmt.Println("Waiting for finished Workers")
	wg.Wait()
	acc.Finish()
	fmt.Println("All done")

	elapsed := time.Since(start)

	fmt.Printf("Took %s for %d packets\n", elapsed, acc.Get("sum"))
	fmt.Println("Writing report")

	f, _ := os.Create(output)
	w := csv.NewWriter(f)

	for line := range acc.GetCsv() {
		if err := w.Write(line); err != nil {
			log.Fatalln("error writing record to csv:", err)
		}
	}

	// Write any buffered data to the underlying writer (standard output).
	w.Flush()

	if err := w.Error(); err != nil {
		log.Fatal(err)
	}

}

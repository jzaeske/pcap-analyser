package analyser

import (
	"./parser"
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
	workers     []parser.Pcap
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

	for i := 0; i < a.workerCount; i++ {
		worker := parser.NewPcap(fmt.Sprintf("Worker %d", i), files)
		wg.Add(1)
		a.workers = append(a.workers, worker)
		go worker.Run(&wg)
	}

	for _, file := range a.pcaps {
		files <- file
	}
	close(files)

	fmt.Println("Waiting for finished Workers")
	wg.Wait()
	fmt.Println("All done")

	elapsed := time.Since(start)

	fmt.Printf("Took %s\n", elapsed)
	fmt.Println("Writing report")

	f, _ := os.Create(output)
	w := csv.NewWriter(f)

	result := a.workers[0].Acc
	for i, w := range a.workers {
		if i == 0 {
			continue
		}
		result.Merge(w.Acc)
	}

	fmt.Println(result.Summary())

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
}

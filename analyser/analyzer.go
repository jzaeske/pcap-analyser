package analyser

import (
	"./components"
	"./report"
	"encoding/csv"
	"fmt"
	"github.com/google/gopacket"
	"log"
	"os"
	"sync"
	"time"
)

type PacketFilter interface {
	Run(filterInstruction string)
	Yes() <-chan gopacket.Packet
	No() <-chan gopacket.Packet
	Input(<-chan gopacket.Packet)
}

type Worker interface {
	Run(wg *sync.WaitGroup)
	Acc() *report.Accumulator
}

type Analyzer struct {
	pcaps       []string
	workerCount int
	workers     []Worker
}

func NewAnalyzer(pcaps []string, concurrentFiles int) (a *Analyzer) {
	a = &Analyzer{}
	a.pcaps = pcaps
	a.workerCount = concurrentFiles
	return
}

func (a *Analyzer) Run(summary bool) {

	start := time.Now()

	var files = make(chan string)
	var wg = sync.WaitGroup{}

	for i := 0; i < a.workerCount; i++ {
		var worker Worker
		if summary {
			worker = components.NewSummary(fmt.Sprintf("Worker %d", i), files)
		} else {
			worker = components.NewPcap(fmt.Sprintf("Worker %d", i), files)
		}
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

}

func (a *Analyzer) ExportCsv(output string) {
	fmt.Println("Writing report")

	f, _ := os.Create(output)
	w := csv.NewWriter(f)

	result := a.workers[0].Acc()
	for i, w := range a.workers {
		if i == 0 {
			continue
		}
		result.Merge(*w.Acc())
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

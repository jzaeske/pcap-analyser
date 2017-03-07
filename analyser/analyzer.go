package analyser

import (
	"./components"
	"encoding/csv"
	"fmt"
	"github.com/google/gopacket"
	"log"
	"os"
	"./chains"
	"time"
	"./report"
)

type PacketFilter interface {
	Run(filterInstruction string)
	Yes() <-chan gopacket.Packet
	No() <-chan gopacket.Packet
	Input(<-chan gopacket.Packet)
}

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
		chain, wg := chains.GenerateExampleChain()
		var worker = components.NewFileWorker(fmt.Sprintf("Worker %d", i), chain)
		a.workers = append(a.workers, worker)
		go worker.Run(files, wg)
	}

	for _, file := range a.pcaps {
		files <- file
	}
	close(files)

	components.WaitForFileWorkers()

	elapsed := time.Since(start)

	fmt.Printf("Took %s\n", elapsed)

}

func (a *Analyzer) ExportCsv(output string) {
	fmt.Println("Writing report")

	f, _ := os.Create(output)
	w := csv.NewWriter(f)

	result := report.GetJoinedAccumulator("_")

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

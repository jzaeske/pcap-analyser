package parser

import (
	"fmt"
	"github.com/google/gopacket/pcapgo"
	"sync"
	"os"
	"bufio"
	"../report"
	"encoding/binary"
	"log"
)

var (
	bufferSize int = 128 * 1024 * 1024 // 128M
	darknetMAC uint64 = 0x000c29027be7
)

type Pcap struct {
	name     string
	nextFile chan string
	Acc      report.Accumulator
	r        *bufio.Reader
}

func NewPcap(name string, nextFile chan string) (p Pcap) {
	p.name = name
	p.nextFile = nextFile
	p.Acc = report.NewAccumulator([]string{"ethIn", "ethInBytes", "ethOut", "ethOutBytes", })
	return
}

func (p *Pcap) Run(wg *sync.WaitGroup) {
	defer wg.Done()
	for file := range p.nextFile {
		p.handleFile(file)
	}
	fmt.Printf("Worker %s finished", p.name)
}

func (p *Pcap) handleFile(file string) {
	f, _ := os.Open(file)
	defer f.Close()

	// Empty old Buffer and set underlying Reader to new file
	p.r = bufio.NewReaderSize(f, bufferSize)

	if r, err := pcapgo.NewReader(p.r); err != nil {
		panic(err)
	} else {
		fmt.Printf("Worker %s handles file %s\n", p.name, file)
		for {
			data, ci, err := r.ReadPacketData()
			if err != nil {
				log.Println(err)
				break;
			}
			date := ci.Timestamp.Format("2006/01/02")

			destMac:= binary.BigEndian.Uint64(append([]byte{0, 0}, data[0:6]...))
			if destMac == darknetMAC {
				p.Acc.Increment(date, "ethIn")
				p.Acc.IncrementValue(date, "ethInBytes", len(data))
			} else {
				p.Acc.Increment(date, "ethOut")
				p.Acc.IncrementValue(date, "ethOutBytes", len(data))
			}
		}
	}
}

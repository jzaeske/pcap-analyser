package parser

import (
	"fmt"
	"github.com/google/gopacket/pcap"
	"sync"
)

type Pcap struct {
	name     string
	nextFile chan string
	Acc      chan string
}

func NewPcap(name string, nextFile chan string) (p Pcap) {
	p.name = name
	p.nextFile = nextFile
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
	if handle, err := pcap.OpenOffline(file); err != nil {
		panic(err)
	} else {
		fmt.Printf("Worker %s handles file %s\n", p.name, file)
		for {
			_, ci, err := handle.ZeroCopyReadPacketData()
			if err != nil {
				break
			}

			p.Acc <- "sum"
			p.Acc <- ci.Timestamp.Format("2006/01/02")
		}
	}
}

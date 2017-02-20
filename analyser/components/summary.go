package components

import (
	"../report"
	"bufio"
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket/pcapgo"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

type Summary struct {
	name     string
	nextFile chan string
	acc      report.Accumulator
	r        *bufio.Reader
}

func NewSummary(name string, nextFile chan string) (p Summary) {
	p.name = name
	p.acc = report.NewAccumulator([]string{"dateMin", "dateMax", "ethIn", "ethInBytes", "ethOut", "ethOutBytes"})
	p.nextFile = nextFile
	return
}

func (p Summary) Acc() *report.Accumulator {
	return &p.acc
}

func (p Summary) Run(wg *sync.WaitGroup) {
	defer wg.Done()
	for file := range p.nextFile {
		p.handleFile(file)
	}
	fmt.Printf("Worker %s finished\n", p.name)
}

func (p *Summary) handleFile(file string) {
	f, err := os.Open(file)
	if err != nil {
		log.Panic(err)
		return
	}
	defer f.Close()

	// add a large buffer between File Reader and gcapgo to reduce the amount of IO reads to the filesystem
	p.r = bufio.NewReaderSize(f, bufferSize)

	if r, err := pcapgo.NewReader(p.r); err != nil {
		log.Panic(err)
	} else {
		fmt.Printf("Worker %s handles file %s\n", p.name, file)
		filename := normalizeFilename(file)
		var minDate = time.Date(2017, 12, 31, 0, 0, 0, 0, time.UTC)
		var maxDate = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
		for {
			data, ci, err := r.ReadPacketData()
			if err != nil {
				if err == io.EOF {
					// ok: that's usual
					break
				} else if err == io.ErrUnexpectedEOF {
					// not so usual, but we can accept it. There are some bytes in the buffer
					// we can try to parse. But we should log here
					// we break next time when we get EOF
					log.Printf("got %x with %d bytes not filled completely\n", err, len(data))
				} else {
					break
				}

			}

			date := ci.Timestamp
			if date.After(maxDate) {
				maxDate = date
			}
			if date.Before(minDate) {
				minDate = date
			}

			destMac := binary.BigEndian.Uint64(append([]byte{0, 0}, data[0:6]...))
			if destMac == darkNetMAC {
				p.acc.Increment(filename, "ethIn")
				p.acc.IncrementValue(filename, "ethInBytes", len(data))
			} else {
				p.acc.Increment(filename, "ethOut")
				p.acc.IncrementValue(filename, "ethOutBytes", len(data))
			}
		}
		p.acc.SetValue(filename, "dateMin", int(minDate.Unix()))
		p.acc.SetValue(filename, "dateMax", int(maxDate.Unix()))
		fmt.Println("finished")
	}
}

func normalizeFilename(filename string) string {
	return filename[strings.LastIndex(filename, "/")+1:]
}

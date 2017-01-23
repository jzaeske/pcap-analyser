package parser

import (
	"../report"
	"bufio"
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"io"
	"log"
	"os"
	"sync"
)

var (
	bufferSize int    = 128 * 1024 * 1024 // 128M
	darkNetMAC uint64 = 0x000c29027be7
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
	p.Acc = report.NewAccumulator([]string{"ethIn", "ethInBytes", "ethOut", "ethOutBytes", "udp", "tcpIn", "tcpSyn", "tcpDataBytes", "tcpAck", "udpDataBytes", "transportOther"})
	return
}

func (p *Pcap) Run(wg *sync.WaitGroup) {
	defer wg.Done()
	for file := range p.nextFile {
		p.handleFile(file)
	}
	fmt.Printf("Worker %s finished\n", p.name)
}

func (p *Pcap) handleFile(file string) {
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
		for {
			data, ci, err := r.ReadPacketData()
			if err != nil {
				if err != io.EOF {
					// we expect err to be io.EOF at the end of the file.
					// Other error message are worth to be announced
					log.Println(err)
				}
				break
			}
			date := ci.Timestamp.Format("2006/01/02")

			destMac := binary.BigEndian.Uint64(append([]byte{0, 0}, data[0:6]...))
			if destMac == darkNetMAC {
				p.Acc.Increment(date, "ethIn")
				p.Acc.IncrementValue(date, "ethInBytes", len(data))

				packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Lazy)
				if packet.TransportLayer() != nil {
					switch packet.TransportLayer().LayerType() {
					case layers.LayerTypeUDP:
						udpLayer := packet.Layer(layers.LayerTypeUDP)
						udp, _ := udpLayer.(*layers.UDP)
						p.Acc.Increment(date, "udp")
						p.Acc.IncrementValue(date, "udpDataBytes", len(udp.LayerPayload()))
					case layers.LayerTypeTCP:
						p.Acc.Increment(date, "tcpIn")
						tcpLayer := packet.Layer(layers.LayerTypeTCP)
						tcp, _ := tcpLayer.(*layers.TCP)
						if tcp.SYN {
							p.Acc.Increment(date, "tcpSyn")
						}
						if tcp.ACK {
							p.Acc.Increment(date, "tcpAck")
						}
						p.Acc.IncrementValue(date, "tcpDataBytes", len(tcp.LayerPayload()))
					default:
						p.Acc.Increment(date, "transportOther")
					}
				}
			} else {
				p.Acc.Increment(date, "ethOut")
				p.Acc.IncrementValue(date, "ethOutBytes", len(data))
			}
		}
	}
}

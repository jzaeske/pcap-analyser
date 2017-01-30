package filter

import (
	"github.com/google/gopacket"
)

type Ethernet struct {
	input chan gopacket.Packet
	yes   chan gopacket.Packet
	no    chan gopacket.Packet
}

func (eth *Ethernet) Input(in chan gopacket.Packet) {
	eth.input = in
}

func (eth *Ethernet) Yes() <-chan gopacket.Packet {
	return eth.yes
}

func (eth *Ethernet) No() <-chan gopacket.Packet {
	return eth.no
}

func (eth *Ethernet) Run() {
	defer close(eth.yes)
	defer close(eth.no)
	if eth.input != nil {
		for packet := range eth.input {
			eth.yes <- packet
		}
	}
}

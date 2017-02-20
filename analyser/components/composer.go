package components

import (
	"github.com/google/gopacket"
)

type Composer struct {
	input  chan gopacket.Packet
	output chan gopacket.Packet
}

func (composer *Composer) Output() <-chan gopacket.Packet {
	return composer.output
}

func (composer *Composer) Run() {
	defer close(composer.output)
	if composer.input != nil {
		for packet := range composer.input {
			composer.output <- packet
		}
	}
}

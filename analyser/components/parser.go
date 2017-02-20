package components

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Parser struct {
	Id     int `xml:"id,attr"`
	Input  chan UnparsedMeasurement
	output chan Measurement
}

func NewParser(in *chan UnparsedMeasurement) (p *Parser) {
	return &Parser{
		Input:  *in,
		output: make(chan Measurement, 2000),
	}
}

func (p *Parser) Output() *chan Measurement {
	return &p.output
}

func (p *Parser) Run() {
	defer close(p.output)
	if p.Input != nil {
		for unparsed := range p.Input {
			packet := gopacket.NewPacket(*unparsed.Data, layers.LayerTypeEthernet, gopacket.Lazy)
			p.output <- Measurement{&packet, unparsed.CaptureInfo}
		}
	}
}

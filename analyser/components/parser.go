package components

import (
	. "../chains"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var ParserOptions = gopacket.DecodeOptions{Lazy: true}

type Parser struct {
	Id        string `xml:"id,attr"`
	Input     chan UnparsedMeasurement
	output    chan Measurement
	pubOutput bool
}

func (p *Parser) Copy() Component {
	return &Parser{Id: p.Id}
}

func (p *Parser) Init() {
	p.output = make(chan Measurement, CHANNEL_BUFFER_SIZE)
}

func (p *Parser) ComId() string {
	return p.Id
}

func (p *Parser) Output() *chan Measurement {
	p.pubOutput = true
	return &p.output
}

func (p *Parser) OpenChannels() []interface{} {
	var open = []interface{}{}
	if !p.pubOutput {
		open = append(open, &p.output)
	}
	return open
}

func (p *Parser) Run() {
	if p.Input != nil {
		for unparsed := range p.Input {
			packet := gopacket.NewPacket(*unparsed.Data, layers.LayerTypeEthernet, ParserOptions)
			p.output <- Measurement{Packet: &packet, CaptureInfo: unparsed.CaptureInfo, Start: unparsed.Start}
		}
	}
	defer close(p.output)
}

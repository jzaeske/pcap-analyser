package components

import (
	. "../chains"
	"github.com/google/gopacket/layers"
	"os"
	"bufio"
	"github.com/google/gopacket/pcapgo"
)

type PacketOutput struct {
	Id        string `xml:"id,attr"`
	OutputFile string `xml:"outputFile,attr"`
	input     chan Measurement
	output    chan Measurement
	pubOutput bool
}

func (p *PacketOutput) Copy() Component {
	return &PacketOutput{Id: p.Id, OutputFile: p.OutputFile}
}

func (p *PacketOutput) Init() {
	p.output = make(chan Measurement, CHANNEL_BUFFER_SIZE)
}

func (p *PacketOutput) ComId() string {
	return p.Id
}

func (p *PacketOutput) Input(input *chan Measurement) {
	p.input = *input
}

func (p *PacketOutput) Output() *chan Measurement {
	p.pubOutput = true
	return &p.output
}

func (p *PacketOutput) OpenChannels() []interface{} {
	var open = []interface{}{}
	if !p.pubOutput {
		open = append(open, &p.output)
	}
	return open
}

func (p *PacketOutput) Run() {
	if p.Input != nil {
		f, _ := os.Create(p.OutputFile)
		buf := bufio.NewWriterSize(f, 4*1024*1024)
		w := pcapgo.NewWriter(buf)
		w.WriteFileHeader(65536, layers.LinkTypeEthernet)
		defer buf.Flush()
		defer f.Close()

		for measurement := range p.input {
			w.WritePacket(*measurement.CaptureInfo, (*measurement.Packet).Data())
			p.output <- measurement
		}
	}
	defer close(p.output)
}

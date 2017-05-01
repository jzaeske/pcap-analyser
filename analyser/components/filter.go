package components

import (
	. "../chains"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func createBPFFromString(instruction string) (*pcap.BPF, error) {
	if bpfInstructions, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, 65536, instruction); err != nil {
		return nil, err
	} else {
		dummyHandle := pcap.Handle{}
		if bpf, err := dummyHandle.NewBPFInstructionFilter(bpfInstructions); err != nil {
			return nil, err
		} else {
			return bpf, nil
		}
	}
}

type Filter struct {
	Id        string `xml:"id,attr"`
	Criteria  string `xml:"bpf,attr"`
	input     chan Measurement
	output    chan Measurement
	no        chan Measurement
	pubOutput bool
	pubNo     bool
}

type BackscatterFilter struct {
	Id        string `xml:"id,attr"`
	input     chan TCPStream
	output    chan TCPStream
	other     chan TCPStream
	pubOutput bool
	pubOther  bool
}

func (f *Filter) Copy() Component {
	return &Filter{Id: f.Id, Criteria: f.Criteria}
}

func (f *Filter) Init() {
	f.output = make(chan Measurement, CHANNEL_BUFFER_SIZE)
	f.no = make(chan Measurement, CHANNEL_BUFFER_SIZE)
}

func (f *Filter) ComId() string {
	return f.Id
}

func (f *Filter) Input(input *chan Measurement) {
	f.input = *input
}

func (f *Filter) Output() *chan Measurement {
	f.pubOutput = true
	return &f.output
}

func (f *Filter) No() *chan Measurement {
	f.pubNo = true
	return &f.no
}

func (f *Filter) OpenChannels() []interface{} {
	var open = []interface{}{}
	if !f.pubOutput {
		open = append(open, &f.output)
	}
	if !f.pubNo {
		open = append(open, &f.no)
	}
	return open
}

func (f *Filter) Run() {
	defer close(f.output)
	defer close(f.no)

	if bpf, err := createBPFFromString(f.Criteria); err != nil {
		panic(err)
	} else {
		if f.input != nil {
			for measurement := range f.input {
				if bpf.Matches(*measurement.CaptureInfo, (*measurement.Packet).Data()) {
					f.output <- measurement
				} else {
					f.no <- measurement
				}
			}
		}
	}
}

func (b *BackscatterFilter) Copy() Component {
	return &BackscatterFilter{Id: b.Id}
}

func (b *BackscatterFilter) Init() {
	b.output = make(chan TCPStream, CHANNEL_BUFFER_SIZE)
	b.other = make(chan TCPStream, CHANNEL_BUFFER_SIZE)
}

func (b *BackscatterFilter) ComId() string {
	return b.Id
}

func (b *BackscatterFilter) Input(input *chan TCPStream) {
	b.input = *input
}

func (b *BackscatterFilter) Output() *chan TCPStream {
	b.pubOutput = true
	return &b.output
}

func (b *BackscatterFilter) Other() interface{} {
	b.pubOther = true
	return &b.other
}

func (b *BackscatterFilter) OpenChannels() []interface{} {
	var open = []interface{}{}
	if !b.pubOutput {
		open = append(open, &b.output)
	}
	if !b.pubOther {
		open = append(open, &b.other)
	}
	return open
}

func (b *BackscatterFilter) Run() {
	defer close(b.output)
	defer close(b.other)

	if b.input != nil {
		for stream := range b.input {
			if stream.Handshake[0] == false {
				b.output <- stream
			} else {
				b.other <- stream
			}
		}
	}

}

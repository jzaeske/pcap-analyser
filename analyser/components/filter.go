package components

import (
	. "../chains"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"time"
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
	MinTime   string `xml:"minTime,attr"`
	MaxTime   string `xml:"maxTime,attr"`
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
	return &Filter{Id: f.Id, Criteria: f.Criteria, MinTime: f.MinTime, MaxTime: f.MaxTime}
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
		var minTime, maxTime *time.Time
		if min, err := time.Parse("2006/01/02 15:04:05", f.MinTime); err == nil {
			minTime = &min
		} else {
			minTime = nil
		}
		if max, err := time.Parse("2006/01/02 15:04:05", f.MaxTime); err == nil {
			maxTime = &max
		} else {
			maxTime = nil
		}
		if f.input != nil {
			for measurement := range f.input {
				if minTime != nil && minTime.After((*measurement.CaptureInfo).Timestamp) {
					f.no <- measurement
					continue
				}
				if maxTime != nil && maxTime.Before((*measurement.CaptureInfo).Timestamp) {
					f.no <- measurement
					continue
				}

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

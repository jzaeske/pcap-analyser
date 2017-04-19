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
	criteria string
	input    chan Measurement
	output   chan Measurement
	no       chan Measurement
}

func NewFilter(ch PacketChain, instructions string) (f *Filter) {
	return &Filter{
		criteria: instructions,
		input:    *ch.Output(),
		output:   make(chan Measurement, CHANNEL_BUFFER_SIZE),
		no:       make(chan Measurement, CHANNEL_BUFFER_SIZE),
	}
}

func (f *Filter) Output() *chan Measurement {
	return &f.output
}

func (f *Filter) No() *chan Measurement {
	return &f.no
}

func (f *Filter) Run() {
	defer close(f.output)
	defer close(f.no)

	if bpf, err := createBPFFromString(f.criteria); err != nil {
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

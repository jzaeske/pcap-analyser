package components

import (
	"../../statistics"
	. "../chains"
)

type Stat struct {
	p2     *statistics.P2
	mean   *statistics.Mean
	input  chan Measurement
	output chan Measurement
}

func NewStat(ch PacketChain, p float64) (c *Stat) {
	return &Stat{
		p2:     statistics.NewP2(p),
		mean:   statistics.NewMean(),
		input:  *ch.Output(),
		output: make(chan Measurement, CHANNEL_BUFFER_SIZE),
	}
}

func NewStatFromFilter(f *Filter, p float64) (c *Stat) {
	return &Stat{
		p2:     statistics.NewP2(p),
		mean:   statistics.NewMean(),
		input:  *f.No(),
		output: make(chan Measurement, CHANNEL_BUFFER_SIZE),
	}
}

func (s *Stat) Output() *chan Measurement {
	return &s.output
}

func (s *Stat) Run() {
	defer close(s.output)

	if s.input != nil {
		for packet := range s.input {
			value := float64(len((*packet.Packet).Data()))

			s.mean.AddFloat(value)
			s.p2.AddValue(value)

			s.output <- packet
		}
	}
}

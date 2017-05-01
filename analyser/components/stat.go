package components

import (
	"../../statistics"
	. "../chains"
)

type Stat struct {
	Id        string  `xml:"id,attr"`
	P         float64 `xml:"p,attr"`
	p2        *statistics.P2
	mean      *statistics.Mean
	input     chan Measurement
	output    chan Measurement
	pubOutput bool
}

func (s *Stat) ComId() string {
	return s.Id
}

func (s *Stat) Init() {
	s.p2 = statistics.NewP2(s.P)
	s.mean = statistics.NewMean()
	s.output = make(chan Measurement, CHANNEL_BUFFER_SIZE)
}

func (s *Stat) OpenChannels() []interface{} {
	var open = []interface{}{}
	if !s.pubOutput {
		open = append(open, &s.output)
	}
	return open
}

func (s *Stat) Copy() Component {
	return &Stat{Id: s.Id, P: s.P}
}

func (s *Stat) Input(input *chan Measurement) {
	s.input = *input
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

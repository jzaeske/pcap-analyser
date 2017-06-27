package components

import (
	. "../chains"
	"encoding/xml"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
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

type StreamFilter struct {
	Id        string `xml:"id,attr"`
	Policy    string `xml:"policy,attr"`
	Comp      []ScoreComparator
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
		log.Println(f.Criteria)
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
				if measurement.Start {
					// signaling packet
					f.no <- measurement
					f.output <- measurement
					continue
				}

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

func (b *StreamFilter) Copy() Component {
	result := &StreamFilter{Id: b.Id, Policy: b.Policy}
	for _, c := range b.Comp {
		result.Comp = append(result.Comp, *&c)
	}
	return result
}

func (b *StreamFilter) Init() {
	b.output = make(chan TCPStream, CHANNEL_BUFFER_SIZE)
	b.other = make(chan TCPStream, CHANNEL_BUFFER_SIZE)
}

func (b *StreamFilter) ComId() string {
	return b.Id
}

func (b *StreamFilter) Input(input *chan TCPStream) {
	b.input = *input
}

func (b *StreamFilter) Output() *chan TCPStream {
	b.pubOutput = true
	return &b.output
}

func (b *StreamFilter) Other() interface{} {
	b.pubOther = true
	return &b.other
}

func (b *StreamFilter) OpenChannels() []interface{} {
	var open = []interface{}{}
	if !b.pubOutput {
		open = append(open, &b.output)
	}
	if !b.pubOther {
		open = append(open, &b.other)
	}
	return open
}

func (f *StreamFilter) Run() {
	defer close(f.output)
	defer close(f.other)

	if f.input != nil {
		for stream := range f.input {

			count, max := 0, len(f.Comp)

			for _, c := range f.Comp {
				if match := c.Compare(&stream); match {
					count++
				}
			}

			if f.Policy == "or" && count > 0 {
				f.output <- stream
			} else if f.Policy == "and" && count == max {
				f.output <- stream
			} else {
				f.other <- stream
			}
		}
	}

}

type ScoreComparator struct {
	Score string `xml:"score,attr"`
	Min   int    `xml:"min,attr"`
	Max   int    `xml:"max,attr"`
}

func (comp *ScoreComparator) Compare(stream *TCPStream) bool {
	if comp.Min > 0 && stream.GetScore(comp.Score) < comp.Min {
		return false
	}
	if comp.Max != 0 && stream.GetScore(comp.Score) > comp.Max {
		return false
	}
	return true
}

func (f *StreamFilter) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	for _, attr := range start.Attr {
		if attr.Name.Local == "id" {
			f.Id = attr.Value
		}
		if attr.Name.Local == "policy" {
			f.Policy = attr.Value
		}
	}
	for {
		t, err := d.Token()
		if err != nil {
			return err
		}
		var sc *ScoreComparator
		switch tt := t.(type) {
		case xml.StartElement:
			switch tt.Name.Local {
			case "ScoreComparator":
				sc = new(ScoreComparator)
			}

			if sc != nil {
				err = d.DecodeElement(sc, &tt)
				if err != nil {
					return err
				}
				f.Comp = append(f.Comp, *sc)
			}
		case xml.EndElement:
			if tt == start.End() {
				return nil
			}
		}
	}

	return nil
}

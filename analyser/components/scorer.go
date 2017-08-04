package components

import (
	"encoding/xml"
	. "github.com/jzaeske/pcap-analyser/analyser/chains"
	"github.com/jzaeske/pcap-analyser/analyser/score"
)

type StreamScorer struct {
	Id        string `xml:"id,attr"`
	input     chan TCPStream
	output    chan TCPStream
	Scores    []score.StreamScore
	pubOutput bool
}

func (s *StreamScorer) Copy() Component {
	result := &StreamScorer{Id: s.Id}
	for _, sc := range s.Scores {
		result.Scores = append(result.Scores, *&sc)
	}
	return result
}

func (s *StreamScorer) Init() {
	s.output = make(chan TCPStream, CHANNEL_BUFFER_SIZE)
}

func (s *StreamScorer) ComId() string {
	return s.Id
}

func (s *StreamScorer) Input(input *chan TCPStream) {
	s.input = *input
}

func (s *StreamScorer) Output() *chan TCPStream {
	s.pubOutput = true
	return &s.output
}

func (s *StreamScorer) Other() interface{} {
	return nil
}

func (s *StreamScorer) OpenChannels() []interface{} {
	var open = []interface{}{}
	if !s.pubOutput {
		open = append(open, &s.output)
	}
	return open
}

func (s *StreamScorer) Run() {
	defer close(s.output)

	if s.input != nil {
		for stream := range s.input {

			if len(s.Scores) > 0 {
				for _, scorer := range s.Scores {
					value := scorer.Value(&stream)
					stream.AddScore(scorer.Score(), value)
					stream.AddScore(scorer.Identifier(), value)
				}
			}

			s.output <- stream
		}
	}

}

func (f *StreamScorer) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	for _, attr := range start.Attr {
		if attr.Name.Local == "id" {
			f.Id = attr.Value
		}
	}
	for {
		t, err := d.Token()
		if err != nil {
			return err
		}
		var sc score.StreamScore
		switch tt := t.(type) {
		case xml.StartElement:
			switch tt.Name.Local {
			case "ZmapFPScore":
				sc = new(score.ZmapFPScore)
			case "MasscanFPScore":
				sc = new(score.MasscanFPScore)
			case "HandshakeScore":
				sc = new(score.Handshake)
			case "PayloadScore":
				sc = new(score.Payload)
			case "DurationScore":
				sc = new(score.Duration)
			}

			if sc != nil {
				err = d.DecodeElement(sc, &tt)
				if err != nil {
					return err
				}
				f.Scores = append(f.Scores, sc)
			}
		case xml.EndElement:
			if tt == start.End() {
				return nil
			}
		}
	}

	return nil
}

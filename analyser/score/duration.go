package score

import . "github.com/jzaeske/pcap-analyser/analyser/chains"

type Duration struct {
	Id  string `xml:"identifier,attr"`
	Sc  string `xml:"score,attr"`
	Min int    `xml:"minMillis,attr"`
	Max int    `xml:"maxMillis,attr"`
}

func (d *Duration) Identifier() string {
	return d.Id
}

func (d *Duration) Score() string {
	return d.Sc
}

func (d *Duration) Value(s *TCPStream) int {
	duration := int(s.End.Unix()-s.Start.Unix())*1000 + ((s.End.Nanosecond() - s.Start.Nanosecond()) / 1000000)
	if d.Min > 0 && duration < d.Min {
		return 0
	}
	if d.Max != 0 && duration > d.Max {
		return 0
	}
	return 1
}

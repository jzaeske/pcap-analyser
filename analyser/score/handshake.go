package score

import (
	. "github.com/jzaeske/pcap-analyser/analyser/chains"
	"strconv"
	"strings"
)

type Handshake struct {
	Id      string `xml:"identifier,attr"`
	Pattern string `xml:"pattern,attr"`
	Sc      string `xml:"score,attr"`
	mask    []int
}

func (m *Handshake) Identifier() string {
	return m.Id
}

func (m *Handshake) Score() string {
	return m.Sc
}

func (m *Handshake) Value(s *TCPStream) int {
	if m.mask == nil {
		parts := strings.Split(m.Pattern, ",")
		m.mask = make([]int, len(parts))
		for i, part := range parts {
			m.mask[i], _ = strconv.Atoi(part)
		}
	}

	for i, expected := range m.mask {

		if expected == 1 && s.Handshake[i] != true {
			return 0
		}
		if expected == -1 && s.Handshake[i] != false {
			return 0
		}
	}

	return 1
}

package score

import (
	. "../chains"
	"encoding/hex"
)

type Payload struct {
	Id  string `xml:"identifier,attr"`
	Hex string `xml:"hexVal,attr"`
	Sc  string `xml:"score,attr"`
}

func (m *Payload) Identifier() string {
	return m.Id
}

func (m *Payload) Score() string {
	return m.Sc
}

func (m *Payload) Value(s *TCPStream) int {
	if m.Hex == "" {
		if s.Bytes() == 0 {
			return 1
		}
		return 0
	}

	length := len(m.Hex) / 2
	if length > s.Bytes() {
		return 0
	}

	payload := s.Payload[0:length]
	if hex.EncodeToString(payload) == m.Hex {
		return 1
	}

	return 0
}

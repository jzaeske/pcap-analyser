package score

import (
	. "github.com/jzaeske/pcap-analyser/analyser/chains"
)

const ZMAP_IDENTIFIER = 54321

type ZmapFPScore struct {
	Id string `xml:"identifier,attr"`
	Sc string `xml:"score,attr"`
}

func (z *ZmapFPScore) Identifier() string {
	return z.Id
}

func (z *ZmapFPScore) Score() string {
	return z.Sc
}

func (z *ZmapFPScore) Value(s *TCPStream) int {
	if len(s.Identifiers) == 0 {
		return 0
	}

	for _, idPair := range s.Identifiers {
		id := idPair.Identifier
		if id != ZMAP_IDENTIFIER {
			return 0
		}
	}

	return 1
}

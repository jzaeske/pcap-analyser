package score

import . "../chains"
import "encoding/binary"

// ip_id = ip_them ^ port_them ^ seqno;
type MasscanFPScore struct {
	Id string `xml:"identifier,attr"`
	Sc string `xml:"score,attr"`
}

func masscanCalculateIdentifier(dstIp uint32, dstPort uint16, seqNo uint32) uint16 {
	return uint16(dstIp) ^ dstPort ^ uint16(seqNo)
}

func (m *MasscanFPScore) Identifier() string {
	return m.Id
}

func (m *MasscanFPScore) Score() string {
	return m.Sc
}

func (m *MasscanFPScore) Value(s *TCPStream) int {
	if len(s.Identifiers) == 0 {
		return 0
	}

	for _, idPair := range s.Identifiers {
		dstIp := binary.BigEndian.Uint32(s.Network.Dst().Raw())
		dstPort := binary.BigEndian.Uint16(s.Transport.Dst().Raw())
		msId := masscanCalculateIdentifier(dstIp, dstPort, idPair.Tcp.Seq)
		if idPair.Identifier != msId {
			return 0
		}
	}
	return 1
}

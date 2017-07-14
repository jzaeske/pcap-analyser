package classifier

import (
	. "../chains"
	"encoding/hex"
)

type PayloadClassifier struct {
	Identifier string `xml:"identifier,attr"`
	Bytes      int    `xml:"bytes,attr"`
	Offset     int    `xml:"offset,attr"`
}

// General Classifier

func (p PayloadClassifier) ColumnIdentifier() string {
	return p.Identifier
}

func (p PayloadClassifier) GroupName() string {
	return "date"
}

// Packet Classifier

func (p PayloadClassifier) GroupKey(measurement *Measurement) string {
	transportLayer := (*measurement.Packet).TransportLayer()

	fetchLength := p.Bytes + p.Offset

	if transportLayer != nil {
		payload := transportLayer.LayerPayload()
		if len(payload) < p.Offset {
			return ""
		}
		if len(payload) < fetchLength {
			return hex.EncodeToString(payload[p.Offset:])
		}
		part := transportLayer.LayerPayload()[p.Offset:fetchLength]
		return hex.EncodeToString(part)
	}
	return UNCLASSIFIED
}

// Stream Classifier

func (p PayloadClassifier) GroupKeyStream(s *TCPStream) string {
	fetchLength := p.Bytes + p.Offset

	if len(s.Payload) < p.Offset {
		return ""
	}
	if len(s.Payload) < fetchLength {
		return hex.EncodeToString(s.Payload[p.Offset:])
	}

	return hex.EncodeToString(s.Payload[p.Offset:fetchLength])
}

func (i PayloadClassifier) Rev() {}

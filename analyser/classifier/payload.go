package classifier

import (
	. "../chains"
	"encoding/hex"
)

type PayloadClassifier struct {
	Identifier string `xml:"identifier,attr"`
	Bytes      int    `xml:"bytes,attr"`
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
	if transportLayer != nil {
		if len(transportLayer.LayerPayload()) < p.Bytes {
			return hex.EncodeToString(transportLayer.LayerPayload())
		}
		payload := transportLayer.LayerPayload()[0:p.Bytes]
		return hex.EncodeToString(payload)
	}
	return UNCLASSIFIED
}

// Stream Classifier

func (p PayloadClassifier) GroupKeyStream(s *TCPStream) string {
	if len(s.Payload) >= p.Bytes {
		payload := s.Payload[0:p.Bytes]
		return hex.EncodeToString(payload)
	}
	return hex.EncodeToString(s.Payload)
}

func (i PayloadClassifier) Rev() {}

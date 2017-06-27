package classifier

import (
	. "../chains"
	"strconv"
)

type TransportClassifier struct {
	Identifier string `xml:"identifier,attr"`
}

// General Classifier

func (i TransportClassifier) GroupName() string {
	return "transport"
}

func (i TransportClassifier) ColumnIdentifier() string {
	return i.Identifier
}

// PacketClassifier

func (i TransportClassifier) GroupKey(measurement *Measurement) string {
	protocolField := (*measurement.Packet).Data()[9]

	return strconv.Itoa(int(protocolField))
}

package classifier

import (
	. "../chains"
	"strconv"
	"encoding/hex"
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
	protocolField := (*measurement.Packet).Data()[14+9]

	if protocolField == 47 {
		inner := (*measurement.Packet).Data()[34+2:34+4]
		return "GRE_" + hex.EncodeToString(inner)
	}

	return strconv.Itoa(int(protocolField))
}

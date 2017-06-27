package classifier

import (
	. "../chains"
	"github.com/google/gopacket/layers"
)

type IcmpClassifier struct {
	Identifier string `xml:"identifier,attr"`
}

// General Classifier

func (i IcmpClassifier) GroupName() string {
	return "icmp"
}

func (i IcmpClassifier) ColumnIdentifier() string {
	return i.Identifier
}

// PacketClassifier

func (i IcmpClassifier) GroupKey(measurement *Measurement) string {
	if icmpLayer := (*measurement.Packet).Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		icmpPacket, _ := icmpLayer.(*layers.ICMPv4)
		return icmpPacket.TypeCode.String()
	}
	return UNCLASSIFIED
}

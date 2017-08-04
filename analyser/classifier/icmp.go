package classifier

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	. "github.com/jzaeske/pcap-analyser/analyser/chains"
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
	var result string
	if icmpLayer := (*measurement.Packet).Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		icmpPacket, _ := icmpLayer.(*layers.ICMPv4)
		result = icmpPacket.TypeCode.String()

		// Check for AR Packet in ICMP Payload
		if innerPacket := gopacket.NewPacket(icmpPacket.LayerPayload(), layers.LayerTypeIPv4, gopacket.Lazy); innerPacket != nil {
			innerIpLayer := innerPacket.Layer(layers.LayerTypeIPv4)
			outerIpLayer := (*measurement.Packet).Layer(layers.LayerTypeIPv4)
			if innerIpLayer != nil && outerIpLayer != nil {
				innerIpPacket, _ := innerIpLayer.(*layers.IPv4)
				outerIpPacket, _ := outerIpLayer.(*layers.IPv4)
				if innerIpPacket.SrcIP.Equal(outerIpPacket.DstIP) {
					if innerTcpLayer := innerPacket.Layer(layers.LayerTypeTCP); innerTcpLayer != nil {
						innerTcpPacket := innerTcpLayer.(*layers.TCP)
						if innerTcpPacket.ACK {
							result += "_AR"
						}
					}
				}
			}
		}

		return result
	}
	return UNCLASSIFIED
}

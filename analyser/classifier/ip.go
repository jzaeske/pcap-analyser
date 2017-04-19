package classifier

import (
	. "../chains"
	"github.com/google/gopacket/layers"
	"net"
)

type Ip4Classifier struct {
	Identifier string
	Reverse    bool
	CIDR       int
	mask       net.IPMask
}

// General Classifier

func (i Ip4Classifier) GroupName() string {
	return "source"
}

func (i Ip4Classifier) ColumnIdentifier() string {
	return i.Identifier
}

// PacketClassifier

func (i Ip4Classifier) GroupKey(measurement *Measurement) string {
	if i.mask == nil && i.CIDR >= 0 && i.CIDR <= 32 {
		i.mask = net.CIDRMask(i.CIDR, 32-i.CIDR)
	}
	ipLayer := (*measurement.Packet).Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ipPacket, _ := ipLayer.(*layers.IPv4)
		var ip net.IP
		if i.Reverse {
			ip = ipPacket.SrcIP
		} else {
			ip = ipPacket.DstIP
		}

		return ipOrNetwork(ip, i.mask)

	}
	return UNCLASSIFIED
}

func (i Ip4Classifier) MetaGroup(measurement *Measurement) string {
	return UNCLASSIFIED
}

// Stream Classifier

func (i Ip4Classifier) GroupKeyStream(stream *TCPStream) string {
	if i.Reverse {
		return stream.Network.Dst().String()
	}
	return stream.Network.Src().String()
}

func (i Ip4Classifier) MetaGroupStream(stream *TCPStream) string {
	return UNCLASSIFIED
}

func ipOrNetwork(ip net.IP, mask net.IPMask) string {
	if mask == nil {
		ones, _ := mask.Size()
		return ip.Mask(mask).String() + "/" + string(ones)
	} else {
		return ip.String()
	}
}

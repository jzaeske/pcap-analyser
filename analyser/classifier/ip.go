package classifier

import (
	"github.com/google/gopacket/layers"
	. "github.com/jzaeske/pcap-analyser/analyser/chains"
	"net"
	"strconv"
)

type Ip4Classifier struct {
	Identifier string `xml:"identifier,attr"`
	Reverse    bool   `xml:"reverse,attr"`
	CIDR       int    `xml:"cidr,attr"`
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
	if i.mask == nil && i.CIDR > 0 && i.CIDR < 32 {
		i.mask = net.CIDRMask(i.CIDR, 32)
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

// Stream Classifier

func (i Ip4Classifier) GroupKeyStream(stream *TCPStream) string {
	if i.mask == nil && i.CIDR > 0 && i.CIDR < 32 {
		i.mask = net.CIDRMask(i.CIDR, 32)
	}

	if i.mask != nil {
		var ipBytes []byte
		if i.Reverse {
			ipBytes = stream.Network.Src().Raw()
		} else {
			ipBytes = stream.Network.Dst().Raw()
		}
		ip := net.IPv4(ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3])

		return ipOrNetwork(ip, i.mask)
	} else {
		if i.Reverse {
			return stream.Network.Src().String()
		} else {
			return stream.Network.Dst().String()
		}
	}
}

func ipOrNetwork(ip net.IP, mask net.IPMask) string {
	if mask != nil {
		ones, _ := mask.Size()
		return ip.Mask(mask).String() + "/" + strconv.Itoa(ones)
	} else {
		return ip.String()
	}
}

func (i Ip4Classifier) Rev() {
	i.Reverse = !i.Reverse
}

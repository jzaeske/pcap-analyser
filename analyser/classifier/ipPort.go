package classifier

import (
	. "../chains"
	"github.com/google/gopacket/layers"
	"net"
)

type Ip4PortClassifier struct {
	Identifier  string `xml:"identifier,attr"`
	ReverseIp   bool   `xml:"reverseIp,attr"`
	ReversePort bool   `xml:"reversePort,attr"`
	CIDR        int    `xml:"cidr,attr"`
	mask        net.IPMask
}

// General Classifier

func (i Ip4PortClassifier) GroupName() string {
	return "source"
}

func (i Ip4PortClassifier) ColumnIdentifier() string {
	return i.Identifier
}

// PacketClassifier

func (i Ip4PortClassifier) GroupKey(measurement *Measurement) string {
	result := ""

	if i.mask == nil && i.CIDR >= 0 && i.CIDR <= 32 {
		i.mask = net.CIDRMask(i.CIDR, 32)
	}

	ipLayer := (*measurement.Packet).Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ipPacket, _ := ipLayer.(*layers.IPv4)
		var ip net.IP
		if i.ReverseIp {
			ip = ipPacket.DstIP
		} else {
			ip = ipPacket.SrcIP
		}

		result += ipOrNetwork(ip, i.mask)

	} else {
		result += UNCLASSIFIED
	}

	transportLayer := (*measurement.Packet).TransportLayer()
	if transportLayer != nil {
		if i.ReversePort {
			result += ":" + transportLayer.TransportFlow().Src().String()
		}
		result += ":" + transportLayer.TransportFlow().Dst().String()
	} else {
		result += ":_"
	}

	return result
}

// Stream Classifier

func (i Ip4PortClassifier) GroupKeyStream(stream *TCPStream) string {
	//result := stream.Start.Format("2006/01/02 15")
	result := ""
	if i.mask == nil && i.CIDR > 0 && i.CIDR < 32 {
		i.mask = net.CIDRMask(i.CIDR, 32)
	}

	if i.mask != nil {
		var ipBytes []byte
		if i.ReverseIp {
			ipBytes = stream.Network.Src().Raw()
		} else {
			ipBytes = stream.Network.Dst().Raw()
		}
		ip := net.IPv4(ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3])

		result += ipOrNetwork(ip, i.mask)
	} else {
		if i.ReverseIp {
			result += stream.Network.Src().String()
		} else {
			result += stream.Network.Dst().String()
		}
	}

	if i.ReversePort {
		result += ":" + stream.Transport.Src().String()
	} else {
		result += ":" + stream.Transport.Dst().String()
	}

	return result
}

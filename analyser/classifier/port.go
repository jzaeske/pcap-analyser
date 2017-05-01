package classifier

import . "../chains"

type PortClassifier struct {
	Identifier string `xml:"identifier,attr"`
	Reverse    bool   `xml:"reverse,attr"`
}

// General Classifier

func (p PortClassifier) ColumnIdentifier() string {
	return p.Identifier
}

func (PortClassifier) GroupName() string {
	return "port"
}

// PacketClassifier

func (p PortClassifier) GroupKey(measurement *Measurement) string {
	transportLayer := (*measurement.Packet).TransportLayer()
	if transportLayer != nil {
		if p.Reverse {
			return transportLayer.TransportFlow().Src().String()
		}
		return transportLayer.TransportFlow().Dst().String()
	}
	return UNCLASSIFIED
}

func (p PortClassifier) MetaGroup(measurement *Measurement) string {
	networkLayer := (*measurement.Packet).NetworkLayer()
	if networkLayer != nil {
		if p.Reverse {
			return networkLayer.NetworkFlow().Src().String()
		}
		return networkLayer.NetworkFlow().Dst().String()
	}
	return UNCLASSIFIED
}

// Stream Classifier

func (p PortClassifier) GroupKeyStream(stream *TCPStream) string {
	if p.Reverse {
		return stream.Transport.Src().String()
	}
	return stream.Transport.Dst().String()
}

func (p PortClassifier) MetaGroupStream(stream *TCPStream) string {
	if p.Reverse {
		return stream.Network.Src().String()
	}
	return stream.Network.Dst().String()
}

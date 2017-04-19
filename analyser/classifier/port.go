package classifier

type PortClassifier struct {
	Identifier string
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
		return transportLayer.TransportFlow().Dst().String()
	}
	return UNCLASSIFIED
}

func (p PortClassifier) MetaGroup(measurement *Measurement) string {
	networkLayer := (*measurement.Packet).NetworkLayer()
	if networkLayer != nil {
		return networkLayer.NetworkFlow().Dst().String()
	}
	return UNCLASSIFIED
}

// Stream Classifier

func (p PortClassifier) GroupKeyStream(stream *TCPStream) string {
	return stream.Transport.Dst().String()
}

func (p PortClassifier) MetaGroupStream(stream *TCPStream) string {
	return stream.Network.Dst().String()
}

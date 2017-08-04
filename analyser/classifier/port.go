package classifier

import . "github.com/jzaeske/pcap-analyser/analyser/chains"

type PortClassifier struct {
	Identifier string `xml:"identifier,attr"`
	Reverse    bool   `xml:"reverse,attr"`
	Both       bool   `xml:"both,attr"`
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
		fl := transportLayer.TransportFlow()
		if p.Reverse {
			if p.Both {
				return fl.Src().String() + "/" + fl.Dst().String()
			}
			return fl.Src().String()
		}
		if p.Both {
			return fl.Dst().String() + "/" + fl.Src().String()
		}
		return fl.Dst().String()
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

func (p PortClassifier) Rev() {
	p.Reverse = !p.Reverse
}

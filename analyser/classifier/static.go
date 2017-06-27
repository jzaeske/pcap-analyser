package classifier

import (
	. "../chains"
)

type StaticClassifier struct {
	Identifier string `xml:"identifier,attr"`
	Filename   string `xml:"filename,attr"`
}

// General Classifier

func (p StaticClassifier) ColumnIdentifier() string {
	return p.Identifier
}

func (p StaticClassifier) GroupName() string {
	return "static"
}

// Packet Classifier

func (p StaticClassifier) GroupKey(measurement *Measurement) string {
	return p.Filename
}

// Stream Classifier

func (p StaticClassifier) GroupKeyStream(s *TCPStream) string {
	return p.Filename
}

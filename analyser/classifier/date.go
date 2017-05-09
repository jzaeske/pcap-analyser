package classifier

import . "../chains"

const DATE_FORMAT = "2006/01/02"

type DayClassifier struct {
	Identifier string `xml:"identifier,attr"`
	Format     string `xml:"format,attr"`
}

// General Classifier

func (d DayClassifier) ColumnIdentifier() string {
	return d.Identifier
}

func (d DayClassifier) GroupName() string {
	return "date"
}

// Packet Classifier

func (d DayClassifier) GroupKey(measurement *Measurement) string {
	return measurement.CaptureInfo.Timestamp.Format(d.Format)
}

func (DayClassifier) MetaGroup(measurement *Measurement) string {
	return UNCLASSIFIED
}

// Stream Classifier

func (d DayClassifier) GroupKeyStream(s *TCPStream) string {
	return s.Start.Format(d.Format)
}

func (DayClassifier) MetaGroupStream(stream *TCPStream) string {
	return UNCLASSIFIED
}

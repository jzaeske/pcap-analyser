package classifier

import . "../chains"

const DATE_FORMAT = "2006/01/02"

type DayClassifier struct {
	Identifier string
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
	return measurement.CaptureInfo.Timestamp.Format(DATE_FORMAT)
}

func (DayClassifier) MetaGroup(measurement *Measurement) string {
	return UNCLASSIFIED
}

// Stream Classifier

func (DayClassifier) GroupKeyStream(s *TCPStream) string {
	return s.Start.Format(DATE_FORMAT)
}

func (DayClassifier) MetaGroupStream(stream *TCPStream) string {
	return UNCLASSIFIED
}

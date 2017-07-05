package classifier

import . "../chains"

const UNCLASSIFIED = "_"

type general interface {
	GroupName() string
	ColumnIdentifier() string
}

type PacketClassifier interface {
	general
	GroupKey(measurement *Measurement) string
}

type StreamClassifier interface {
	general
	GroupKeyStream(s *TCPStream) string
	Rev()
}

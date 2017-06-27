package score

import (
	. "../chains"
)

type StreamScore interface {
	Value(s *TCPStream) int
	Identifier() string
	Score() string
}

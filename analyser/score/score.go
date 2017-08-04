package score

import (
	. "github.com/jzaeske/pcap-analyser/analyser/chains"
)

type StreamScore interface {
	Value(s *TCPStream) int
	Identifier() string
	Score() string
}

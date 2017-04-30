package chains

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	r "github.com/google/gopacket/reassembly"
	"time"
)

const HEADER_LIMIT = 20

type StreamChain interface {
	Output() *chan TCPStream
	Other() interface{}
}

type TCPStream struct {
	// Markers for SYN, SYN-ACK, ACK of TCP Handshake
	Handshake []bool
	// Basic Information Flow of Network and Transport Layer
	Network, Transport gopacket.Flow
	// All TCP Headers for this Stream
	Headers               []*layers.TCP
	headerAdditionalBytes int
	headerAdditionalCount int
	// Recieved Payload
	Payload      []byte
	keepPayload  bool
	payloadBytes int
	// Start and EndTime of the Stream
	Dismissed  int
	Start, End time.Time
	packets    int
	next       *chan TCPStream
}

func (s *TCPStream) HandshakeComplete() bool {
	return s.Handshake[0] && s.Handshake[1] && s.Handshake[2]
}

func (s *TCPStream) Bytes() int {
	if s.keepPayload {
		return len(s.Payload)
	}
	return s.payloadBytes
}

func (s *TCPStream) PayloadPackets() int {
	return s.packets
}

func (s *TCPStream) AllPackets() int {
	return len(s.Headers) + s.headerAdditionalCount
}

func (s *TCPStream) HeaderSize() int {
	sum := s.headerAdditionalBytes
	for _, header := range s.Headers {
		sum += len(header.LayerContents())
	}
	return sum
}

func (s *TCPStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir r.TCPFlowDirection, ackSeq r.Sequence, start *bool, ac r.AssemblerContext) bool {
	if tcp.SYN {
		if tcp.ACK {
			s.Handshake[1] = true
		} else {
			s.Handshake[0] = true
		}
	} else if tcp.ACK {
		s.Handshake[2] = true
	}
	if len(s.Headers) < HEADER_LIMIT {
		s.Headers = append(s.Headers, tcp)
	} else {
		s.headerAdditionalCount++
		s.headerAdditionalBytes = len(tcp.LayerContents())
	}

	timestamp := ac.GetCaptureInfo().Timestamp
	if timestamp.After(s.End) {
		s.End = timestamp
	}

	if !tcp.SYN && !s.Handshake[0] {
		return false
	}

	return true
}

func (s *TCPStream) ReassembledSG(sg r.ScatterGather, ac r.AssemblerContext) {
	length, _ := sg.Lengths()
	if s.keepPayload {
		data := sg.Fetch(length)
		s.Payload = append(s.Payload, data...)
	} else {
		s.payloadBytes += length
	}

	s.packets += sg.Stats().Packets
}

func (s *TCPStream) ReassemblyComplete(ac r.AssemblerContext) bool {
	// TODO: Hier könnte das Problem liegen. In Verbindung mit Mutex im Flush
	// Mutex verhindert, dass der Reciever kommt und mehr closes als Buffer
	// blocken.
	*s.next <- *s
	return false
}

type TCPStreamFactory struct {
	Next        *chan TCPStream
	KeepPayload bool
}

func (sf TCPStreamFactory) New(netFlow, tcpFlow gopacket.Flow, tcp *layers.TCP, ac r.AssemblerContext) r.Stream {
	s := &TCPStream{
		Handshake:   make([]bool, 3),
		Network:     netFlow,
		Transport:   tcpFlow,
		Start:       ac.GetCaptureInfo().Timestamp,
		next:        sf.Next,
		keepPayload: sf.KeepPayload,
	}
	s.End = s.Start
	return s
}

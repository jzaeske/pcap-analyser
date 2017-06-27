package chains

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	r "github.com/google/gopacket/reassembly"
	"strconv"
	"time"
)

const HEADER_LIMIT = 20

type StreamChain interface {
	Output() *chan TCPStream
	Other() interface{}
}

type StreamInput interface {
	Input(*chan TCPStream)
}

type TcpContext struct {
	Ci      gopacket.CaptureInfo
	Id      uint16
	Reverse bool
}

func (c TcpContext) GetCaptureInfo() gopacket.CaptureInfo {
	return c.Ci
}

func (c TcpContext) GetIdentifier() uint16 {
	return c.Id
}

type IdentifierPair struct {
	Identifier uint16
	Tcp        *layers.TCP
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

	// Keyed by the Index in Headers
	Identifiers []IdentifierPair

	// Scores
	scores map[string]int
	counts map[string]int

	// Received Payload
	Payload      []byte
	keepPayload  bool
	payloadBytes int
	// Start and EndTime of the Stream
	Dismissed  int
	Start, End time.Time
	packets    int
	next       *chan TCPStream
	finished   bool
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

var dropped = 0

func (s *TCPStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir r.TCPFlowDirection, ackSeq r.Sequence, start *bool, ac r.AssemblerContext) bool {
	if s.finished {
		if (tcp.ACK || tcp.FIN) && !tcp.SYN && !tcp.RST {
			// pure ack at end of connection. not countable anymore, but ok
			return true
		} else if !tcp.SYN {
			*start = true
			return true
		} else {
			return false
		}
	}

	if tcp.SYN {
		if tcp.ACK {
			s.Handshake[1] = true
		} else {
			s.Handshake[0] = true
		}
	} else if tcp.ACK && s.Handshake[1] {
		s.Handshake[2] = true
	}

	if len(s.Headers) < HEADER_LIMIT {
		s.Headers = append(s.Headers, tcp)
	} else {
		s.headerAdditionalCount++
		s.headerAdditionalBytes = len(tcp.LayerContents())
	}

	if dir == r.TCPDirClientToServer && len(s.Identifiers) < 20 {
		if context, ok := ac.(TcpContext); ok {
			s.Identifiers = append(s.Identifiers, IdentifierPair{context.GetIdentifier(), tcp})
		}
	}

	s.addCounts(tcp, dir)

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

	s.addCountsSg(sg)
}

func (s *TCPStream) ReassemblyComplete(ac r.AssemblerContext) bool {
	s.finished = true
	*s.next <- *s
	return false
}

func (s *TCPStream) addCounts(tcp *layers.TCP, dir r.TCPFlowDirection) {
	var prefix = "c"
	if dir == r.TCPDirServerToClient {
		prefix = "s"
	}

	if tcp.SYN {
		s.addCount(prefix, "syn")
	}
	if tcp.ACK {
		s.addCount(prefix, "ack")
	}
	if tcp.RST {
		s.addCount(prefix, "rst")
	}
	if tcp.FIN {
		s.addCount(prefix, "fin")
	}
}

func (s *TCPStream) addCountsSg(sg r.ScatterGather) {
	dir, _, _, _ := sg.Info()

	var prefix = "c"
	if dir == r.TCPDirServerToClient {
		prefix = "s"
	}

	s.addCountValue(prefix, "pck", sg.Stats().Packets)
	length, _ := sg.Lengths()
	s.addCountValue(prefix, "bytes", length)
}

func (s *TCPStream) addCount(prefix, count string) {
	s.addCountValue(prefix, count, 1)
}

func (s *TCPStream) addCountValue(prefix, count string, value int) {
	key := prefix + "_" + count
	if _, ok := s.counts[key]; ok {
		s.counts[key] += value
	} else {
		s.counts[key] = value
	}
}

func (s *TCPStream) GetCount(count string) int {
	if sc, ok := s.counts[count]; ok {
		return sc
	}
	return 0
}

func (s *TCPStream) eachCount(callback func(string, int)) {
	for key, value := range s.counts {
		callback(key, value)
	}
}

func (s *TCPStream) AddScore(score string, value int) {
	if _, ok := s.scores[score]; ok {
		s.scores[score] += value
	} else {
		s.scores[score] = value
	}
}

func (s *TCPStream) GetScore(score string) int {
	if sc, ok := s.scores[score]; ok {
		return sc
	}
	return 0
}

func (s *TCPStream) EachScore(callback func(string, int)) {
	for key, value := range s.scores {
		callback(key, value)
	}
}

func (s *TCPStream) GetCsv(fields []string) []string {
	result := make([]string, len(fields))

	for i, field := range fields {
		switch field {
		case "c_ip":
			result[i] = s.Network.Src().String()
		case "s_ip":
			result[i] = s.Network.Dst().String()
		case "c_port":
			result[i] = s.Transport.Src().String()
		case "s_port":
			result[i] = s.Transport.Dst().String()
		case "t_start":
			result[i] = s.Start.Format("2006/01/02 15:04:05")
		case "t_dur":
			result[i] = strconv.Itoa(int(s.End.Unix()-s.Start.Unix())*1000 + ((s.End.Nanosecond() - s.Start.Nanosecond()) / 1000000))
		default:
			if val, ok := s.scores[field]; ok {
				result[i] = strconv.Itoa(val)
			} else if val, ok := s.counts[field]; ok {
				result[i] = strconv.Itoa(val)
			} else {
				result[i] = "0"
			}
		}
	}

	return result
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
		scores:      make(map[string]int),
		counts:      make(map[string]int),
	}
	s.End = s.Start
	return s
}

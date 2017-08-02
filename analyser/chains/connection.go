package chains

import (
	"../report"
	"encoding/hex"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	r "github.com/jzaeske/gopacket/reassembly"
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
	Ci        gopacket.CaptureInfo
	Id        uint16
	Reverse   bool
	Dir       r.TCPFlowDirection
	SwitchDir bool
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

	PendingPackets int
	PendingBytes   int
	OverlapPackets int
	OverlapBytes   int

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

	errorLog *report.Accumulator
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
	var context TcpContext
	context, ok := ac.(TcpContext)
	if ok && context.SwitchDir {
		if dir != context.Dir {
			dir = context.Dir
		}
	}

	if s.finished {
		s.dropLog("late", tcp, dir)
		return false
	}

	if tcp.SYN {
		if tcp.ACK {
			s.Handshake[1] = true
		} else if !tcp.RST && !tcp.FIN {
			s.Handshake[0] = true
		} else {
			s.Handshake[3] = true
		}
	} else if tcp.ACK && (s.Handshake[1] || s.Handshake[0]) {
		s.Handshake[2] = true
	}

	if len(s.Headers) == 0 && tcp.SYN && tcp.ACK {
		*start = true
	}

	if len(s.Headers) < HEADER_LIMIT {
		s.Headers = append(s.Headers, tcp)
	} else {
		s.headerAdditionalCount++
		s.headerAdditionalBytes = len(tcp.LayerContents())
	}

	if dir == r.TCPDirClientToServer && len(s.Identifiers) < 20 {
		s.Identifiers = append(s.Identifiers, IdentifierPair{context.GetIdentifier(), tcp})
	}

	s.addCounts(tcp, dir)

	timestamp := ac.GetCaptureInfo().Timestamp
	if timestamp.After(s.End) {
		s.End = timestamp
	}

	if !s.Handshake[1] && !s.Handshake[0] {
		if tcp.RST && dir == r.TCPDirClientToServer && len(s.Headers) == 1 {
			// if there was no handshake and this is an rst, this might be backscatter. set flag
			s.Handshake[3] = true
		} else {
			s.dropLog("noHs", tcp, dir)
		}
		s.AddScore("score_nohs", 1)
		return false
	}

	return true
}

func (s *TCPStream) dropLog(typ string, tcp *layers.TCP, dir r.TCPFlowDirection) {
	key := "_"
	if len(tcp.LayerContents()) > 13 {
		key = strconv.Itoa(int(tcp.LayerContents()[13] & 0x1F))
	}
	var prefix = "c_"
	if dir == r.TCPDirServerToClient {
		prefix = "s_"
	}

	s.errorLog.Increment(prefix+key, typ+"Packets")
	s.errorLog.IncrementValue(prefix+key, typ+"Bytes", len(tcp.LayerPayload()))
}

func (s *TCPStream) ReassembledSG(sg r.ScatterGather, ac r.AssemblerContext) {
	length, _ := sg.Lengths()

	if !s.finished {
		if s.keepPayload {
			data := sg.Fetch(length)
			s.Payload = append(s.Payload, data...)
		} else {
			s.payloadBytes += length
		}
		sg.Info()

		s.PendingBytes += sg.Stats().QueuedBytes
		s.PendingPackets += sg.Stats().QueuedPackets
		s.OverlapBytes += sg.Stats().OverlapBytes
		s.OverlapPackets += sg.Stats().OverlapPackets

		s.packets += sg.Stats().Packets

		s.addCountsSg(sg)
	}
}

func (s *TCPStream) ReassemblyComplete(ac r.AssemblerContext) bool {
	if !s.finished {
		s.finished = true
		*s.next <- *s
		return true
	} else {
		return false
	}
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

	s.addCount(prefix, "pck")
	s.addCountValue(prefix, "all_bytes", len(tcp.Payload))
}

func (s *TCPStream) addCountsSg(sg r.ScatterGather) {
	dir, _, _, _ := sg.Info()

	var prefix = "c"
	if dir == r.TCPDirServerToClient {
		prefix = "s"
	}

	s.addCountValue(prefix, "ra_pck", sg.Stats().Packets)
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
		case "payload":
			result[i] = hex.EncodeToString(s.Payload)
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
	Errors      *report.Accumulator
}

func (sf TCPStreamFactory) New(netFlow, tcpFlow gopacket.Flow, tcp *layers.TCP, ac r.AssemblerContext) r.Stream {
	s := &TCPStream{
		Handshake:   []bool{false, false, false, false},
		Network:     netFlow,
		Transport:   tcpFlow,
		Start:       ac.GetCaptureInfo().Timestamp,
		next:        sf.Next,
		keepPayload: sf.KeepPayload,
		scores:      make(map[string]int),
		counts:      make(map[string]int),
		errorLog:    sf.Errors,
		finished:    false,
	}
	s.End = s.Start
	return s
}

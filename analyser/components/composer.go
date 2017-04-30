package components

import (
	. "../chains"
	"../report"
	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	r "github.com/google/gopacket/reassembly"
	"time"
)

var moveDuration, _ = time.ParseDuration("30s")
var deleteDuration, _ = time.ParseDuration("-1m")

type Composer struct {
	counter      report.Accumulator
	input        chan Measurement
	output       chan TCPStream
	other        chan Measurement
	defragmenter *ip4defrag.IPv4Defragmenter
	assembler    *r.Assembler
	pool         *r.StreamPool
	keepPayload  bool
}

type tcpContext gopacket.CaptureInfo

func (c tcpContext) GetCaptureInfo() gopacket.CaptureInfo {
	return gopacket.CaptureInfo(c)
}

func NewComposer(ch PacketChain, keepPayload bool) (c *Composer) {
	c = &Composer{
		input:       *ch.Output(),
		output:      make(chan TCPStream),
		other:       make(chan Measurement, CHANNEL_BUFFER_SIZE),
		keepPayload: keepPayload,
		counter:     report.GenerateAccumulator("reassembly"),
	}
	c.resetAssembler()
	return
}

func (c *Composer) resetAssembler() {
	c.defragmenter = ip4defrag.NewIPv4Defragmenter()
	c.pool = r.NewStreamPool(TCPStreamFactory{Next: c.Output(), KeepPayload: c.keepPayload})
	c.assembler = r.NewAssembler(c.pool)
}

func (c *Composer) Output() *chan TCPStream {
	return &c.output
}

func (c *Composer) Other() interface{} {
	return &c.other
}

func (c *Composer) Run() {
	defer close(c.output)
	defer close(c.other)
	var lastFlush time.Time

	if c.input != nil {

		for packet := range c.input {
			// Flush Old on Start of new PCAP-File for clean state
			if packet.Start {
				c.assembler.FlushCloseOlderThan(time.Now())
				// new PCAP file with distinct dst addresses.
				// Reset the assembler
				c.resetAssembler()
			}

			// Get IP and TCP Layer. If both present, reassemble the tcp stream
			// if not, put the packet into the secondary channel
			if ipLayer := (*packet.Packet).Layer(layers.LayerTypeIPv4); ipLayer != nil {
				ipPacket := ipLayer.(*layers.IPv4)

				newIpPacket, err := c.defragmenter.DefragIPv4(ipPacket)
				if err != nil {
					c.counter.Increment("_", err.Error())
					continue
				}
				if newIpPacket == nil {
					continue
				}

				if newIpPacket.Length > ipPacket.Length {
					c.counter.Increment("_", "ip_defrag")
					pb, _ := (*packet.Packet).(gopacket.PacketBuilder)
					nextDecoder := newIpPacket.NextLayerType()
					nextDecoder.Decode(newIpPacket.Payload, pb)
				}

				if tcpLayer := (*packet.Packet).Layer(layers.LayerTypeTCP); tcpLayer != nil {
					if tcpPacket, ok := tcpLayer.(*layers.TCP); ok {
						tcpPacket.SetNetworkLayerForChecksum((*packet.Packet).NetworkLayer())
						c.assembler.AssembleWithContext((*packet.Packet).NetworkLayer().NetworkFlow(), tcpPacket, tcpContext(*packet.CaptureInfo))
					} else {
						c.counter.Increment("_", "tcp_corrupt")
					}
				} else {
					c.other <- packet
				}
			} else {
				c.other <- packet
			}

			// stepped window. If we have not flushed yet or on start of new file
			// reset the last flush timestamp
			if lastFlush.IsZero() || packet.Start {
				lastFlush = (*packet.CaptureInfo).Timestamp
			} else {
				// if last flush is older than step size, delete flush window
				if lastFlush.Add(moveDuration).Before((*packet.CaptureInfo).Timestamp) {
					lastFlush = (*packet.CaptureInfo).Timestamp
					c.assembler.FlushCloseOlderThan(lastFlush.Add(deleteDuration))
					if dis := c.defragmenter.DiscardOlderThan(lastFlush.Add(deleteDuration)); dis > 0 {
						c.counter.IncrementValue("_", "ip_discard_fragments", dis)
					}
				}
			}
		}
		c.assembler.FlushAll()
	}
}

package components

import (
	. "../chains"
	"../report"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/jzaeske/gopacket/ip4defrag"
	r "github.com/jzaeske/gopacket/reassembly"
	"time"
	"net"
)

var moveDuration, _ = time.ParseDuration("30s")
var deleteDuration, _ = time.ParseDuration("-1m")

type Composer struct {
	Id           string `xml:"id,attr"`
	counter      *report.Accumulator
	input        chan Measurement
	output       chan TCPStream
	other        chan Measurement
	pubOutput    bool
	pubOther     bool
	defragmenter *ip4defrag.IPv4Defragmenter
	assembler    *r.Assembler
	pool         *r.StreamPool
	KeepPayload  bool   `xml:"keepPayload,attr"`
	OnlyDefrag   bool   `xml:"onlyDefrag,attr"`
	InEthDst     string `xml:"inEthDst,attr"`
	inEthDst     *net.HardwareAddr
}

func (c *Composer) Copy() Component {
	return &Composer{Id: c.Id, KeepPayload: c.KeepPayload, OnlyDefrag: c.OnlyDefrag, InEthDst: c.InEthDst}
}

func (c *Composer) Init() {
	c.output = make(chan TCPStream, CHANNEL_BUFFER_SIZE)
	c.other = make(chan Measurement, CHANNEL_BUFFER_SIZE)
	c.counter = report.GenerateAccumulator("reassembly")
	c.resetAssembler()

	if c.InEthDst != "" {
		if ethDst, err := net.ParseMAC(c.InEthDst); err == nil {
			c.inEthDst = &ethDst
		}
	}
}

func (c *Composer) ComId() string {
	return c.Id
}

func (c *Composer) Input(input *chan Measurement) {
	c.input = *input
}

func (c *Composer) Output() *chan TCPStream {
	c.pubOutput = true
	return &c.output
}

func (c *Composer) Other() interface{} {
	c.pubOther = true
	return &c.other
}

func (c *Composer) OpenChannels() []interface{} {
	var open = []interface{}{}
	if !c.pubOutput {
		open = append(open, &c.output)
	}
	if !c.pubOther {
		open = append(open, &c.other)
	}
	return open
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
				lastFlush = time.Time{}
				continue
			}

			// Get IP and TCP layer. If both present, reassemble the tcp stream
			// if not, put the packet into the secondary channel
			if ipLayer := (*packet.Packet).Layer(layers.LayerTypeIPv4); ipLayer != nil {
				ipPacket := ipLayer.(*layers.IPv4)

				newIpPacket, err := c.defragmenter.DefragIPv4WithTimestamp(ipPacket, packet.CaptureInfo.Timestamp)
				if err != nil {
					c.counter.Increment("_", err.Error())
					continue
				}
				if newIpPacket == nil {
					continue
				}

				if newIpPacket.Length > ipPacket.Length {
					c.counter.Increment("_", "ip_defrag")
					// Remove Fragment Information on Header
					ipHeader := ipPacket.LayerContents()
					ipHeader[2] = byte((len(newIpPacket.LayerPayload()) + 20) / 256)
					ipHeader[3] = byte((len(newIpPacket.LayerPayload()) + 20) % 256)
					ipHeader[6] = 0
					ipHeader[7] = 0

					// Build new Packet
					ip := append(ipHeader, newIpPacket.LayerPayload()...)
					data := append((*packet.Packet).Data()[0:14], ip...)
					*packet.Packet = gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.Lazy)
				}

				if c.OnlyDefrag {
					c.other <- packet
				} else if tcpLayer := (*packet.Packet).Layer(layers.LayerTypeTCP); tcpLayer != nil {
					if tcpPacket, ok := tcpLayer.(*layers.TCP); ok {
						context := TcpContext{Ci: *packet.CaptureInfo, Id: newIpPacket.Id}
						if c.inEthDst != nil {
							if ethLayer := (*packet.Packet).Layer(layers.LayerTypeEthernet); ethLayer != nil {
								eth, _ := ethLayer.(*layers.Ethernet)
								context.SwitchDir = true
								if eth.DstMAC.String() == c.inEthDst.String() {
									context.Dir = r.TCPDirClientToServer
								} else {
									context.Dir = r.TCPDirServerToClient
								}
							}
						}
						tcpPacket.SetNetworkLayerForChecksum((*packet.Packet).NetworkLayer())
						c.assembler.AssembleWithContext((*packet.Packet).NetworkLayer().NetworkFlow(), tcpPacket, context)
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
			if lastFlush.IsZero() {
				lastFlush = (*packet.CaptureInfo).Timestamp
			} else {
				// if last flush is older than step size, delete flush window
				if lastFlush.Add(moveDuration).Before((*packet.CaptureInfo).Timestamp) {
					lastFlush = (*packet.CaptureInfo).Timestamp
					if !c.OnlyDefrag {
						c.assembler.FlushCloseOlderThan(lastFlush.Add(deleteDuration))
					}
					if dis := c.defragmenter.DiscardOlderThan(lastFlush.Add(deleteDuration)); dis > 0 {
						c.counter.IncrementValue("_", "ip_discard_fragments", dis)
					}
				}
			}
		}
		c.assembler.FlushAll()
	}
}

func (c *Composer) resetAssembler() {
	c.defragmenter = ip4defrag.NewIPv4Defragmenter()
	c.pool = r.NewStreamPool(TCPStreamFactory{Next: c.Output(), KeepPayload: c.KeepPayload, Errors: c.counter})
	c.assembler = r.NewAssembler(c.pool)
}

package components

import (
	. "../chains"
	"../classifier"
	"../report"
	"github.com/google/gopacket"
)

type PacketCounter struct {
	pc     classifier.PacketClassifier
	layer  gopacket.LayerType
	count  report.Accumulator
	input  chan Measurement
	output chan Measurement
}

//noinspection ALL
func NewPacketCounter(ch PacketChain, pc classifier.PacketClassifier, layer gopacket.LayerType) (c *PacketCounter) {
	return &PacketCounter{
		pc:     pc,
		layer:  layer,
		count:  report.GenerateAccumulator(pc.GroupName()),
		input:  *ch.Output(),
		output: make(chan Measurement, CHANNEL_BUFFER_SIZE),
	}
}

func NewPacketCounterFromFilter(f *Filter, pc classifier.PacketClassifier, layer gopacket.LayerType) (c *PacketCounter) {
	return &PacketCounter{
		pc:     pc,
		layer:  layer,
		count:  report.GenerateAccumulator(pc.GroupName()),
		input:  *f.No(),
		output: make(chan Measurement, CHANNEL_BUFFER_SIZE),
	}
}

func NewPacketCounterFromStreamChain(s StreamChain, pc classifier.PacketClassifier, layer gopacket.LayerType) (c *PacketCounter) {
	return &PacketCounter{
		pc:     pc,
		layer:  layer,
		count:  report.GenerateAccumulator(pc.GroupName()),
		input:  *s.Other(),
		output: make(chan Measurement, CHANNEL_BUFFER_SIZE),
	}
}

func (c *PacketCounter) Output() *chan Measurement {
	return &c.output
}

func (c *PacketCounter) Run() {
	defer close(c.output)

	if c.input != nil {
		for packet := range c.input {
			groupKey := c.pc.GroupKey(&packet)
			columnIdentifier := c.pc.ColumnIdentifier()
			if countLayer := (*packet.Packet).Layer(c.layer); countLayer != nil {
				c.count.Increment(groupKey, columnIdentifier)
				c.count.IncrementValue(groupKey, columnIdentifier+"Header", len(countLayer.LayerContents()))
				c.count.IncrementValue(groupKey, columnIdentifier+"Payload", len(countLayer.LayerPayload()))
			} else {
				c.count.Increment(groupKey, "NO_"+columnIdentifier)
			}
			c.output <- packet
		}
	}
}

type StreamCounter struct {
	sc     classifier.StreamClassifier
	count  report.Accumulator
	input  chan TCPStream
	output chan TCPStream
}

func NewStreamCounter(ch StreamChain, sc classifier.StreamClassifier) (c *StreamCounter) {
	return &StreamCounter{
		sc:     sc,
		count:  report.GenerateAccumulator(sc.GroupName()),
		input:  *ch.Output(),
		output: make(chan TCPStream, CHANNEL_BUFFER_SIZE),
	}
}

func (c *StreamCounter) Output() *chan TCPStream {
	return &c.output
}

func (c *StreamCounter) Other() *chan Measurement {
	return nil
}

func (c *StreamCounter) Run() {
	defer close(c.output)

	if c.input != nil {
		for stream := range c.input {
			groupKey := c.sc.GroupKeyStream(&stream)
			columnIdentifier := c.sc.ColumnIdentifier()

			c.count.Increment(groupKey, columnIdentifier)
			c.count.IncrementValue(groupKey, columnIdentifier+"Packets", stream.AllPackets())
			c.count.IncrementValue(groupKey, columnIdentifier+"Bytes", int(stream.Bytes()))

			c.output <- stream
		}
	}
}

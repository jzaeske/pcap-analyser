package components

import (
	"../report"
	"fmt"
	"github.com/google/gopacket"
)

type Counter struct {
	pc     PacketCounter
	layer  gopacket.LayerType
	count  report.Accumulator
	input  chan Measurement
	output chan Measurement
}

func NewCounter(ch Chain, pc PacketCounter, layer gopacket.LayerType) (c *Counter) {
	return &Counter{
		pc:     pc,
		layer:  layer,
		count:  report.GenerateAccumulator("_"),
		input:  *ch.Output(),
		output: make(chan Measurement, 2000),
	}
}

func NewCounterFromFilter(f *Filter, pc PacketCounter, layer gopacket.LayerType) (c *Counter) {
	return &Counter{
		pc:     pc,
		layer:  layer,
		count:  report.GenerateAccumulator("_"),
		input:  *f.No(),
		output: make(chan Measurement, 2000),
	}
}

func (c *Counter) Output() *chan Measurement {
	return &c.output
}

func (c *Counter) Run() {
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
		fmt.Println(c.count.Summary())
	}
}

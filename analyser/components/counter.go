package components

import (
	"../report"
	"fmt"
)

type Counter struct {
	pc     PacketCounter
	count  report.Accumulator
	input  chan Measurement
	output chan Measurement
}

func NewCounter(ch Chain, pc PacketCounter) (c *Counter) {
	return &Counter{
		pc:     pc,
		count:  report.GenerateAccumulator("_"),
		input:  *ch.Output(),
		output: make(chan Measurement, 2000),
	}
}

func NewCounterFromFilter(f *Filter, pc PacketCounter) (c *Counter) {
	return &Counter{
		pc:     pc,
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
			groupKey := c.pc.GroupKey(packet)
			columnIdentifier := c.pc.ColumnIdentifier()
			c.count.Increment(groupKey, columnIdentifier)
			c.count.IncrementValue(groupKey, columnIdentifier+"Data", c.pc.DataLen(packet))
			c.output <- packet
		}
	}
	fmt.Println(c.count.Summary())
}

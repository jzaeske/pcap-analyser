package components

import (
	. "../chains"
	"../classifier"
	"../report"
	"encoding/xml"
	"github.com/google/gopacket"
	"strconv"
)

type PacketCounter struct {
	Id        string `xml:"id,attr"`
	Pc        classifier.PacketClassifier
	MetaC     classifier.PacketClassifier
	LayerId   int `xml:"layer,attr"`
	layer     gopacket.LayerType
	count     map[string]report.Accumulator
	input     chan Measurement
	output    chan Measurement
	pubOutput bool
}

func (c *PacketCounter) Copy() Component {
	return &PacketCounter{Id: c.Id, Pc: *&c.Pc, MetaC: *&c.MetaC, LayerId: c.LayerId}
}

func (c *PacketCounter) Init() {
	c.count = make(map[string]report.Accumulator)
	c.count["_"] = report.GenerateAccumulator(c.Pc.GroupName())
	c.output = make(chan Measurement, CHANNEL_BUFFER_SIZE)
	c.layer = gopacket.LayerType(c.LayerId)
}

func (c *PacketCounter) Input(input *chan Measurement) {
	c.input = *input
}

func (c *PacketCounter) ComId() string {
	return c.Id
}

func (c *PacketCounter) Output() *chan Measurement {
	c.pubOutput = true
	return &c.output
}

func (c *PacketCounter) OpenChannels() []interface{} {
	var open = []interface{}{}
	if !c.pubOutput {
		open = append(open, &c.output)
	}
	return open
}

func (c *PacketCounter) Run() {
	defer close(c.output)

	if c.input != nil {
		for packet := range c.input {
			groupKey := c.Pc.GroupKey(&packet)
			columnIdentifier := c.Pc.ColumnIdentifier()

			counter := c.getAccumulator(&packet)

			if countLayer := (*packet.Packet).Layer(c.layer); countLayer != nil {
				counter.Increment(groupKey, columnIdentifier)
				counter.IncrementValue(groupKey, columnIdentifier+"Header", len(countLayer.LayerContents()))
				counter.IncrementValue(groupKey, columnIdentifier+"Payload", len(countLayer.LayerPayload()))
			} else {
				counter.Increment(groupKey, "NO_"+columnIdentifier)
			}
			c.output <- packet
		}
	}
}

func (c *PacketCounter) getAccumulator(m *Measurement) report.Accumulator {
	if c.MetaC == nil {
		return c.count["_"]
	}

	metaKey := c.MetaC.GroupKey(m)

	if counter, ok := c.count[metaKey]; ok {
		return counter
	} else {
		counter = report.GenerateAccumulator(metaKey)
		c.count[metaKey] = counter
		return counter
	}
}

type StreamCounter struct {
	Id        string `xml:"id,attr"`
	Sc        classifier.StreamClassifier
	MetaC     classifier.StreamClassifier
	count     map[string]report.Accumulator
	input     chan TCPStream
	output    chan TCPStream
	pubOutput bool
}

func (c *StreamCounter) Copy() Component {
	return &StreamCounter{Id: c.Id, Sc: *&c.Sc, MetaC: *&c.Sc}
}

func (c *StreamCounter) Init() {
	c.count = make(map[string]report.Accumulator)
	c.count["_"] = report.GenerateAccumulator(c.Sc.GroupName())
	c.output = make(chan TCPStream, CHANNEL_BUFFER_SIZE)
}

func (c *StreamCounter) ComId() string {
	return c.Id
}

func (c *StreamCounter) Input(input *chan TCPStream) {
	c.input = *input
}

func (c *StreamCounter) Output() *chan TCPStream {
	c.pubOutput = true
	return &c.output
}

func (c *StreamCounter) Other() interface{} {
	return nil
}

func (c *StreamCounter) OpenChannels() []interface{} {
	var open = []interface{}{}
	if !c.pubOutput {
		open = append(open, &c.output)
	}
	return open
}

func (c *StreamCounter) Run() {
	defer close(c.output)

	if c.input != nil {
		for stream := range c.input {
			groupKey := c.Sc.GroupKeyStream(&stream)
			columnIdentifier := c.Sc.ColumnIdentifier()

			counter := c.getAccumulator(&stream)

			counter.Increment(groupKey, columnIdentifier)
			counter.IncrementValue(groupKey, columnIdentifier+"Packets", stream.AllPackets())
			counter.IncrementValue(groupKey, columnIdentifier+"Bytes", int(stream.Bytes()))

			c.output <- stream
		}
	}
}

func (c *StreamCounter) getAccumulator(stream *TCPStream) report.Accumulator {
	if c.MetaC == nil {
		return c.count["_"]
	}

	metaKey := c.MetaC.GroupKeyStream(stream)

	if counter, ok := c.count[metaKey]; ok {
		return counter
	} else {
		counter = report.GenerateAccumulator(metaKey)
		c.count[metaKey] = counter
		return counter
	}
}

// Unmarshalling Code for XML Configuration File

func (c *PacketCounter) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	for _, attr := range start.Attr {
		if attr.Name.Local == "id" {
			c.Id = attr.Value
		} else if attr.Name.Local == "layer" {
			c.LayerId, _ = strconv.Atoi(attr.Value)
		}
	}
	for {
		t, err := d.Token()
		if err != nil {
			return err
		}
		var cl classifier.PacketClassifier
		switch tt := t.(type) {
		case xml.StartElement:
			switch tt.Name.Local {
			case "Ip4Classifier":
				cl = new(classifier.Ip4Classifier)
			case "PortClassifier":
				cl = new(classifier.PortClassifier)
			case "DayClassifier":
				cl = new(classifier.DayClassifier)
			}
			if cl != nil {
				err = d.DecodeElement(cl, &tt)
				if err != nil {
					return err
				}
				if c.Pc == nil {
					c.Pc = cl
				} else {
					c.MetaC = cl
				}
			}
		case xml.EndElement:
			if tt == start.End() {
				return nil
			}
		}
	}
	return nil
}

func (c *StreamCounter) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	for _, attr := range start.Attr {
		if attr.Name.Local == "id" {
			c.Id = attr.Value
		}
	}
	for {
		t, err := d.Token()
		if err != nil {
			return err
		}
		var cl classifier.StreamClassifier
		switch tt := t.(type) {
		case xml.StartElement:
			switch tt.Name.Local {
			case "Ip4Classifier":
				cl = new(classifier.Ip4Classifier)
			case "PortClassifier":
				cl = new(classifier.PortClassifier)
			case "DayClassifier":
				cl = new(classifier.DayClassifier)
			}
			if cl != nil {
				err = d.DecodeElement(cl, &tt)
				if err != nil {
					return err
				}
				c.Sc = cl
			}
		case xml.EndElement:
			if tt == start.End() {
				return nil
			}
		}
	}

	return nil
}

package components

import (
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"encoding/xml"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	. "github.com/jzaeske/pcap-analyser/analyser/chains"
	"github.com/jzaeske/pcap-analyser/analyser/classifier"
	"github.com/jzaeske/pcap-analyser/analyser/report"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

const WRITE_BUFFER_SIZE = 4 * 1024 * 1024

type PacketOutput struct {
	Id         string `xml:"id,attr"`
	OutputFile string `xml:"outputFile,attr"`
	Pc         classifier.PacketClassifier
	input      chan Measurement
	output     chan Measurement
	pubOutput  bool
}

func (p *PacketOutput) Copy() Component {
	return &PacketOutput{Id: p.Id, OutputFile: p.OutputFile, Pc: *&p.Pc}
}

func (p *PacketOutput) Init() {
	p.output = make(chan Measurement, CHANNEL_BUFFER_SIZE)
}

func (p *PacketOutput) ComId() string {
	return p.Id
}

func (p *PacketOutput) Input(input *chan Measurement) {
	p.input = *input
}

func (p *PacketOutput) Output() *chan Measurement {
	p.pubOutput = true
	return &p.output
}

func (p *PacketOutput) OpenChannels() []interface{} {
	var open = []interface{}{}
	if !p.pubOutput {
		open = append(open, &p.output)
	}
	return open
}

func (p *PacketOutput) runWithClassifier() {
	writer := make(map[string]pcapgo.Writer)
	fileBase := OutputDir + "/" + p.OutputFile

	for measurement := range p.input {
		if measurement.Start {
			continue
		}

		class := p.Pc.GroupKey(&measurement)
		var wr pcapgo.Writer

		if w, ok := writer[class]; !ok {
			fileName := strings.Replace(fileBase, "$", class, 1)
			f, _ := os.Create(fileName)
			buf := bufio.NewWriterSize(f, WRITE_BUFFER_SIZE)
			w = *pcapgo.NewWriter(buf)
			w.WriteFileHeader(65536, layers.LinkTypeEthernet)
			wr = w
			writer[class] = w
			defer buf.Flush()
		} else {
			wr = w
		}

		wr.WritePacket(*measurement.CaptureInfo, (*measurement.Packet).Data())
		p.output <- measurement
	}
}

func (p *PacketOutput) Run() {
	defer close(p.output)
	if p.Input != nil {
		errorCounter := report.GenerateAccumulator("error")
		if p.Pc != nil {
			p.runWithClassifier()
			return
		}
		f, _ := os.Create(OutputDir + "/" + p.OutputFile)
		buf := bufio.NewWriterSize(f, WRITE_BUFFER_SIZE)
		w := pcapgo.NewWriter(buf)
		w.WriteFileHeader(65536, layers.LinkTypeEthernet)
		defer buf.Flush()

		for measurement := range p.input {
			if measurement.Start {
				continue
			}
			(*measurement.CaptureInfo).CaptureLength = len((*measurement.Packet).Data())
			if err := w.WritePacket(*measurement.CaptureInfo, (*measurement.Packet).Data()); err != nil {
				errorCounter.Increment("_", err.Error())
			}
			p.output <- measurement
		}
	}
}

func (f *PacketOutput) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	for _, attr := range start.Attr {
		if attr.Name.Local == "id" {
			f.Id = attr.Value
		}
		if attr.Name.Local == "outputFile" {
			f.OutputFile = attr.Value
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
			case "PayloadClassifier":
				cl = new(classifier.PayloadClassifier)
			case "StaticClassifier":
				cl = new(classifier.StaticClassifier)
			case "IcmpClassifier":
				cl = new(classifier.IcmpClassifier)
			case "TransportClassifier":
				cl = new(classifier.TransportClassifier)
			}

			if cl != nil {
				err = d.DecodeElement(cl, &tt)
				if err != nil {
					return err
				}
				f.Pc = cl
			}
		case xml.EndElement:
			if tt == start.End() {
				return nil
			}
		}
	}

	return nil
}

var csvCounter = 0
var csvCounterLock = sync.Mutex{}

type CsvStreamOutput struct {
	Id         string `xml:"id,attr"`
	OutputFile string `xml:"outputFile,attr"`
	Fields     string `xml:"fields,attr"`
	Sc         classifier.StreamClassifier
	input      chan TCPStream
	output     chan TCPStream
	pubOutput  bool
}

func (c *CsvStreamOutput) Copy() Component {
	return &CsvStreamOutput{Id: c.Id, OutputFile: c.OutputFile, Fields: c.Fields, Sc: *&c.Sc}
}

func (c *CsvStreamOutput) Init() {
	c.output = make(chan TCPStream, CHANNEL_BUFFER_SIZE)
}

func (c *CsvStreamOutput) ComId() string {
	return c.Id
}

func (c *CsvStreamOutput) Input(input *chan TCPStream) {
	c.input = *input
}

func (c *CsvStreamOutput) Output() *chan TCPStream {
	c.pubOutput = true
	return &c.output
}

func (c *CsvStreamOutput) OpenChannels() []interface{} {
	var open = []interface{}{}
	if !c.pubOutput {
		open = append(open, &c.output)
	}
	return open
}

func (c *CsvStreamOutput) Run() {
	defer close(c.output)
	if c.Input != nil {
		if c.Sc != nil {
			c.runWithClassifier()
			return
		}
		csvCounterLock.Lock()
		csvCounter++
		c.OutputFile = strings.Replace(OutputDir+"/"+c.OutputFile, "$", strconv.Itoa(csvCounter), -1)
		if err := os.MkdirAll(c.OutputFile, 0777); err != nil {
			log.Println("Unable to create custom dir; Using default")
			c.OutputFile = OutputDir + "/" + strings.Replace(c.OutputFile, "/", "_", -1)
		}
		csvCounterLock.Unlock()
		f, _ := os.Create(c.OutputFile)
		buf := bufio.NewWriterSize(f, WRITE_BUFFER_SIZE)

		var csvWriter csv.Writer
		var gzipWriter *gzip.Writer
		if strings.HasSuffix(c.OutputFile, ".gz") {
			gzipWriter = gzip.NewWriter(buf)
			csvWriter = *csv.NewWriter(gzipWriter)
		} else {
			csvWriter = *csv.NewWriter(buf)
		}

		fieldList := strings.Split(c.Fields, ",")

		csvWriter.Write(fieldList)

		for stream := range c.input {
			csvWriter.Write(stream.GetCsv(fieldList))
			c.output <- stream
		}

		csvWriter.Flush()
		if gzipWriter != nil {
			gzipWriter.Close()
		}
		buf.Flush()
		f.Close()
	}
}

func (c *CsvStreamOutput) runWithClassifier() {
	writer := make(map[string]csv.Writer)

	csvCounterLock.Lock()
	csvCounter++
	c.OutputFile = strings.Replace(c.OutputFile, "$", strconv.Itoa(csvCounter), -1)
	csvCounterLock.Unlock()

	for stream := range c.input {
		class := c.Sc.GroupKeyStream(&stream)
		fieldList := strings.Split(c.Fields, ",")
		var wr csv.Writer

		if w, ok := writer[class]; !ok {
			file := strings.Replace(c.OutputFile, "#", class, 1)
			fileName := OutputDir + "/" + file
			if err := os.MkdirAll(filepath.Dir(fileName), 0777); err != nil {
				log.Println("Unable to create custom dir; Using default")
				fileName = OutputDir + "/" + strings.Replace(file, "/", "_", -1)
			}
			f, _ := os.Create(fileName)
			buf := bufio.NewWriterSize(f, WRITE_BUFFER_SIZE)

			var gzipWriter *gzip.Writer
			if strings.HasSuffix(c.OutputFile, ".gz") {
				gzipWriter = gzip.NewWriter(buf)
				wr = *csv.NewWriter(gzipWriter)
			} else {
				wr = *csv.NewWriter(buf)
			}

			wr.Write(fieldList)
			writer[class] = wr

			// defers are LIFO
			defer f.Close()
			defer buf.Flush()
			if gzipWriter != nil {
				defer gzipWriter.Close()
			}
			defer wr.Flush()
		} else {
			wr = w
		}

		wr.Write(stream.GetCsv(fieldList))
		c.output <- stream

	}
}

func (c *CsvStreamOutput) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	for _, attr := range start.Attr {
		if attr.Name.Local == "id" {
			c.Id = attr.Value
		}
		if attr.Name.Local == "outputFile" {
			c.OutputFile = attr.Value
		}
		if attr.Name.Local == "fields" {
			c.Fields = attr.Value
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
			case "Ip4PortClassifier":
				cl = new(classifier.Ip4PortClassifier)
			case "PortClassifier":
				cl = new(classifier.PortClassifier)
			case "DayClassifier":
				cl = new(classifier.DayClassifier)
			case "PayloadClassifier":
				cl = new(classifier.PayloadClassifier)
			case "StaticClassifier":
				cl = new(classifier.StaticClassifier)
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

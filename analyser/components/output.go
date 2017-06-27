package components

import (
	. "../chains"
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"os"
	"strconv"
	"strings"
	"sync"
)

const WRITE_BUFFER_SIZE = 4 * 1024 * 1024

type PacketOutput struct {
	Id         string `xml:"id,attr"`
	OutputFile string `xml:"outputFile,attr"`
	input      chan Measurement
	output     chan Measurement
	pubOutput  bool
}

func (p *PacketOutput) Copy() Component {
	return &PacketOutput{Id: p.Id, OutputFile: p.OutputFile}
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

func (p *PacketOutput) Run() {
	if p.Input != nil {
		f, _ := os.Create(p.OutputFile)
		buf := bufio.NewWriterSize(f, WRITE_BUFFER_SIZE)
		w := pcapgo.NewWriter(buf)
		w.WriteFileHeader(65536, layers.LinkTypeEthernet)
		defer buf.Flush()

		for measurement := range p.input {
			if measurement.Start {
				continue
			}
			w.WritePacket(*measurement.CaptureInfo, (*measurement.Packet).Data())
			p.output <- measurement
		}
	}
	defer close(p.output)
}

var csvCounter = 0
var csvCounterLock = sync.Mutex{}

type CsvStreamOutput struct {
	Id         string `xml:"id,attr"`
	OutputFile string `xml:"outputFile,attr"`
	Fields     string `xml:"fields,attr"`
	input      chan TCPStream
	output     chan TCPStream
	pubOutput  bool
}

func (c *CsvStreamOutput) Copy() Component {
	return &CsvStreamOutput{Id: c.Id, OutputFile: c.OutputFile, Fields: c.Fields}
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
	if c.Input != nil {
		csvCounterLock.Lock()
		csvCounter++
		c.OutputFile = strings.Replace(c.OutputFile, "$", strconv.Itoa(csvCounter), -1)
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
	defer close(c.output)
}

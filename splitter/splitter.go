package splitter

import (
	"bufio"
	"flag"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"io"
	"log"
	"net"
	"os"
)

var outDir string

func init() {
	flag.StringVar(&outDir, "outDir", ".", "Output Directory for splitted Files")
}

type Splitter struct {
	writer   map[string]*pcapgo.Writer
	buffers  []*bufio.Writer
	criteria string
}

func NewSplitter(criteria string) (s *Splitter) {
	s = &Splitter{criteria: criteria, writer: make(map[string]*pcapgo.Writer), buffers: []*bufio.Writer{}}
	return
}

func (s *Splitter) Run(files []string) {
	for _, file := range files {
		s.handleFile(file)
	}

	for _, w := range s.buffers {
		w.Flush()
	}
}

func (s *Splitter) handleFile(file string) {
	f, err := os.Open(file)
	if err != nil {
		log.Panic(err)
		return
	}
	defer f.Close()

	_, net, _ := net.ParseCIDR(s.criteria)

	// add a large buffer between File Reader and gcapgo to reduce the amount of IO reads to the filesystem
	reader := bufio.NewReaderSize(f, 128*1024*1024)

	if r, err := pcapgo.NewReader(reader); err != nil {
		log.Panic(err)
	} else {
		for {
			data, ci, err := r.ReadPacketData()
			if err != nil {
				if err == io.EOF {
					// ok: that's usual
					break
				} else if err == io.ErrUnexpectedEOF {
					// if capture terminates unexpected it may happen that pcap file is not generated
					// consistent. The last record header claims to have N bytes captured, but the
					// file has only M < N bytes left. In this case the buffer will not get filled
					// completely and pcapgo return an ErrUnexptectedEOF.
					// Those packages should not be considered in an analysis.
					log.Printf("File %s: has unexcepted EOF. Claimed package with %d bytes "+"can not be filled completely and will be ignored in analysis.\n"+"Package Data%v\n", file, len(data), data)
					break
				} else {
					break
				}

			}

			packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Lazy)
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			var lookupIp string

			if ipLayer != nil {
				ip, _ := ipLayer.(*layers.IPv4)

				if net.Contains(ip.DstIP) {
					lookupIp = ip.DstIP.String()
				} else if net.Contains(ip.SrcIP) {
					lookupIp = ip.SrcIP.String()
				} else {
					// should not happen, but we don't know
					lookupIp = "other"
				}
			} else {
				lookupIp = "other"
			}

			if w, ok := s.writer[lookupIp]; ok {
				w.WritePacket(ci, data)
			} else {
				f, _ := os.Create(outDir + "/" + lookupIp + ".pcap")
				buf := bufio.NewWriterSize(f, 4*1024*1024)
				w := pcapgo.NewWriter(buf)
				s.writer[lookupIp] = w
				w.WriteFileHeader(65536, r.LinkType())
				w.WritePacket(ci, data)
				s.buffers = append(s.buffers, buf)
			}
		}
	}

}

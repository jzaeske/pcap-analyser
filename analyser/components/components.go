package components

import "github.com/google/gopacket"
import (
	"encoding/binary"
	"github.com/google/gopacket/layers"
)

const bufferSize int = 128 * 1024 * 1024 // 128M

type Chain interface {
	Output() *chan Measurement
}

type UnparsedMeasurement struct {
	Data        *[]byte
	CaptureInfo *gopacket.CaptureInfo
}

type Measurement struct {
	Packet      *gopacket.Packet
	CaptureInfo *gopacket.CaptureInfo
}

type PacketCounter interface {
	GroupKey(measurement *Measurement) string
	ColumnIdentifier() string
}

type InOutFilter struct{}

func (f InOutFilter) Decide(measurement Measurement) bool {
	packet := measurement.Packet
	var darkNetMAC uint64 = 0x000c29027be7
	data := (*packet).LinkLayer().LayerContents()
	destinationMac := binary.BigEndian.Uint64(append([]byte{0, 0}, data[0:6]...))

	return destinationMac == darkNetMAC
}

type DayCounter struct {
	Identifier string
}

func (d DayCounter) GroupKey(measurement *Measurement) string {
	return measurement.CaptureInfo.Timestamp.Format("2006/01/02")
}
func (d DayCounter) ColumnIdentifier() string {
	return d.Identifier
}

type IpCounter struct {
	Identifier string
	Reverse    bool
}

func (i IpCounter) GroupKey(measurement *Measurement) string {
	ipLayer := (*measurement.Packet).Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ipPacket, _ := ipLayer.(*layers.IPv4)
		if i.Reverse {
			return ipPacket.SrcIP.String()
		}
		return ipPacket.DstIP.String()
	}
	return "_"
}
func (i IpCounter) ColumnIdentifier() string {
	return i.Identifier
}

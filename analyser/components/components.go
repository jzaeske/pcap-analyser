package components

import "github.com/google/gopacket"
import "encoding/binary"

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
	GroupKey(measurement Measurement) string
	DataLen(measurement Measurement) int
	ColumnIdentifier() string
}

type FilterCriteria interface {
	Decide(measurement Measurement) bool
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
	identifier string
}

func (d DayCounter) GroupKey(measurement Measurement) string {
	return measurement.CaptureInfo.Timestamp.Format("2006/01/02")
}
func (d DayCounter) DataLen(measurement Measurement) int {
	return len((*measurement.Packet).Data())
}
func (d DayCounter) ColumnIdentifier() string {
	return d.identifier
}

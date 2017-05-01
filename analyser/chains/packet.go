package chains

import (
	"github.com/google/gopacket"
)

type PacketChain interface {
	Output() *chan Measurement
}

type PacketInput interface {
	Input(*chan Measurement)
}

type UnparsedMeasurement struct {
	Data        *[]byte
	CaptureInfo *gopacket.CaptureInfo
	Start       bool
}

type Measurement struct {
	Packet      *gopacket.Packet
	CaptureInfo *gopacket.CaptureInfo
	Start       bool
}

type PacketSkipper interface {
	IsSkip(string, int) bool
}

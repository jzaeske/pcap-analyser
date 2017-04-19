package chains

import (
	"github.com/google/gopacket"
)

type PacketChain interface {
	Output() *chan Measurement
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

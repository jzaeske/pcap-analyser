package components

import "github.com/jzaeske/pcap-analyser/analyser/chains"

var OutputDir string

type Component interface {
	ComId() string
	Init()
	Run()
	OpenChannels() []interface{}
	Copy() Component
}

func ConvertStreamChain(c Component) (s chains.StreamChain) {
	switch c.(type) {
	case chains.StreamChain:
		s = c.(chains.StreamChain)
	}
	return
}

func ConvertPacketChain(c Component) (s chains.PacketChain) {
	switch c.(type) {
	case chains.PacketChain:
		s = c.(chains.PacketChain)
	}
	return
}

func ConvertFilter(c Component) (f *Filter) {
	switch c.(type) {
	case *Filter:
		f = c.(*Filter)
	}
	return
}

func ConvertStreamInput(c Component) (s chains.StreamInput) {
	switch c.(type) {
	case chains.StreamInput:
		s = c.(chains.StreamInput)
	}
	return
}

func ConvertPacketInput(c Component) (s chains.PacketInput) {
	switch c.(type) {
	case chains.PacketInput:
		s = c.(chains.PacketInput)
	}
	return
}

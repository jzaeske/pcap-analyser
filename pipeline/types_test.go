package pipeline

import (
	"testing"
	"sync"
)

var Sync sync.WaitGroup = sync.WaitGroup{}

var packetsize = 200

type CallbackChain struct {
	NextChain *CallbackChain
}

func (c *CallbackChain) run(data *[]byte) {
	if c.NextChain != nil {
		go c.NextChain.run(data);
	} else {
		Sync.Done()
	}
}

func benchmarkCallback(length int, packetnum int, b *testing.B) {
	data := make([]byte, packetsize)

	var last *CallbackChain = &CallbackChain{}
	var first = last
	for i := 1; i < length; i++ {
		last.NextChain = &CallbackChain{}
		last = last.NextChain
	}
	Sync.Add(packetnum)
	b.ResetTimer()
	for i := 0; i < packetnum; i++ {
		first.run(&data)
	}
	Sync.Wait()
}

type ChannelChain struct {
	NextChain *ChannelChain
	Reader chan *[]byte
}

func (c *ChannelChain) run() {

	for data:= range c.Reader {
		if (c.NextChain != nil) {
			c.NextChain.Reader <- data
		}
	}
	Sync.Done()
}

func benchmarkChannel(length int, packetnum int, b *testing.B) {
	data := make([]byte, packetsize)

	var last *ChannelChain = &ChannelChain{Reader: make(chan *[]byte, 2000)}
	var first = last
	for i := 1; i < length; i++ {
		last.NextChain = &ChannelChain{Reader: make(chan *[]byte, 2000)}
		go last.run()
		last = last.NextChain
	}
	Sync.Add(1)
	b.ResetTimer()
	for i := 0; i < packetnum; i++ {
		first.Reader <- &data
	}
	close(first.Reader)
	Sync.Wait()
}

//func BenchmarkCallback10_100(b *testing.B) {benchmarkCallback(10, 100, b)}
//func BenchmarkChannel10_100(b *testing.B) {benchmarkChannel(10, 100, b)}
//
//func BenchmarkCallback100_100(b *testing.B) {benchmarkCallback(100, 100, b)}
//func BenchmarkChannel100_100(b *testing.B) {benchmarkChannel(10, 100, b)}
//
//func BenchmarkCallback1000_100(b *testing.B) {benchmarkCallback(1000, 100, b)}
//func BenchmarkChannel1000_100(b *testing.B) {benchmarkChannel(1000, 100, b)}
//
//func BenchmarkCallback1000_1000(b *testing.B) {benchmarkCallback(10000, 1000, b)}
//func BenchmarkChannel1000_1000(b *testing.B) {benchmarkChannel(1000, 1000, b)}
//
//
//func BenchmarkCallback1000_10000(b *testing.B) {benchmarkCallback(10000, 10000, b)}
//func BenchmarkChannel1000_10000(b *testing.B) {benchmarkChannel(1000, 10000, b)}
//
func BenchmarkCallback1000_100000(b *testing.B) {benchmarkCallback(10000, 100000, b)}
func BenchmarkChannel1000_100000(b *testing.B) {benchmarkChannel(1000, 100000, b)}
//func BenchmarkChannel100_1000000(b *testing.B) {benchmarkChannel(100, 1000000, b)}
package pipeline

import (
	"testing"
	"sync"
)

var channelSync sync.WaitGroup = sync.WaitGroup{}

var channelPacketsize = 200

type ChannelChain struct {
	NextChain *ChannelChain
	Reader    chan *[]byte
}

func (c *ChannelChain) run() {

	for data := range c.Reader {
		if c.NextChain != nil {
			c.NextChain.Reader <- data
		}
	}
	if c.NextChain == nil {
		channelSync.Done()
	} else {
		close (c.NextChain.Reader)
	}

}

func benchmarkChannel(length int, packetnum int, b *testing.B) {
	data := make([]byte, channelPacketsize)

	var last *ChannelChain = &ChannelChain{Reader: make(chan *[]byte, 500)}
	var first = last
	go first.run()
	for i := 1; i < length; i++ {
		last.NextChain = &ChannelChain{Reader: make(chan *[]byte, 500)}
		last = last.NextChain
		go last.run()
	}
	channelSync.Add(1)
	b.ResetTimer()
	for i := 0; i < packetnum; i++ {
		first.Reader <- &data
	}
	close(first.Reader)
	channelSync.Wait()
}

// 1. fix packets, increasing elements
func BenchmarkChannel_10000_1000(b *testing.B) {benchmarkChannel(10000, 1000, b)}
func BenchmarkChannel_20000_1000(b *testing.B) {benchmarkChannel(20000, 1000, b)}
func BenchmarkChannel_30000_1000(b *testing.B) {benchmarkChannel(30000, 1000, b)}
func BenchmarkChannel_40000_1000(b *testing.B) {benchmarkChannel(40000, 1000, b)}
func BenchmarkChannel_50000_1000(b *testing.B) {benchmarkChannel(50000, 1000, b)}
func BenchmarkChannel_60000_1000(b *testing.B) {benchmarkChannel(60000, 1000, b)}
func BenchmarkChannel_70000_1000(b *testing.B) {benchmarkChannel(70000, 1000, b)}
func BenchmarkChannel_80000_1000(b *testing.B) {benchmarkChannel(80000, 1000, b)}
func BenchmarkChannel_90000_1000(b *testing.B) {benchmarkChannel(90000, 1000, b)}
func BenchmarkChannel_100000_1000(b *testing.B) {benchmarkChannel(100000, 1000, b)}
func BenchmarkChannel_1000000_1000(b *testing.B) {benchmarkChannel(1000000, 1000, b)}

// 2. fix elements, increasing packets
func BenchmarkChannel_100_10000000(b *testing.B) {benchmarkChannel(100, 10000000, b)}
func BenchmarkChannel_100_20000000(b *testing.B) {benchmarkChannel(100, 20000000, b)}
func BenchmarkChannel_100_30000000(b *testing.B) {benchmarkChannel(100, 30000000, b)}
func BenchmarkChannel_100_40000000(b *testing.B) {benchmarkChannel(100, 40000000, b)}
func BenchmarkChannel_100_50000000(b *testing.B) {benchmarkChannel(100, 50000000, b)}
func BenchmarkChannel_100_100000000(b *testing.B) {benchmarkChannel(100, 100000000, b)}
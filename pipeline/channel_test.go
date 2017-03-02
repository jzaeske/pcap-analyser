package pipeline

import (
	"sync"
	"testing"
)

// Synchronization to detect, when the last element has finished
var channelSync sync.WaitGroup = sync.WaitGroup{}

// Size of the Packet. Does not really matter since pointers are send via the channel.
var channelPacketsize = 200

// end marker to detect the last packet for end of current measurement
var endMarker = []byte{42}

// dummy data that is transmitted through the pipeline
var data = make([]byte, channelPacketsize)

// For Benchmark Implementation the element has just two attributes, a channel to read incoming data
// and a successor to pass the data to
type ChannelChain struct {
	NextChain *ChannelChain
	Reader    chan *[]byte
}

// simple run function fo the element. Is called as go routine to run concurrently to other elements
func (c *ChannelChain) run() {
	// read all data of the incoming channel
	for data := range c.Reader {
		// if not the last element of the pipeline, pass the data to the next element
		if c.NextChain != nil {
			c.NextChain.Reader <- data
		} else {
			// if it is the last element of the pipleline and the endMarker of the packet stream is detected.
			// Syncronize the measurement
			if data == &endMarker {
				channelSync.Done()
			}
		}
	}
	// free space after the benchmark has completed
	if c.NextChain != nil {
		close(c.NextChain.Reader)
	}
}

func benchmarkChannel(length int, packetnum int, b *testing.B) {
	// initialization: create pipeline and start the go routines
	var last *ChannelChain = &ChannelChain{Reader: make(chan *[]byte, 250)}
	var first = last
	go first.run()
	for i := 1; i < length; i++ {
		last.NextChain = &ChannelChain{Reader: make(chan *[]byte, 250)}
		last = last.NextChain
		go last.run()
	}
	// reset the timer. do not measure initialization
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		// send the packets through the channel and wait for the pipeline to finish
		channelSync.Add(1)
		for i := 0; i < packetnum; i++ {
			first.Reader <- &data
		}
		first.Reader <- &endMarker
		channelSync.Wait()
	}
	b.StopTimer()
	// free space
	close(first.Reader)
}

// 1. fix packets, increasing elements
func BenchmarkChannel_100_1000(b *testing.B)    { benchmarkChannel(100, 100, b) }
func BenchmarkChannel_1000_1000(b *testing.B)   { benchmarkChannel(1000, 1000, b) }
func BenchmarkChannel_5000_1000(b *testing.B)   { benchmarkChannel(5000, 1000, b) }
func BenchmarkChannel_10000_1000(b *testing.B)  { benchmarkChannel(10000, 1000, b) }
func BenchmarkChannel_20000_1000(b *testing.B)  { benchmarkChannel(20000, 1000, b) }
func BenchmarkChannel_30000_1000(b *testing.B)  { benchmarkChannel(30000, 1000, b) }
func BenchmarkChannel_40000_1000(b *testing.B)  { benchmarkChannel(40000, 1000, b) }
func BenchmarkChannel_50000_1000(b *testing.B)  { benchmarkChannel(50000, 1000, b) }
func BenchmarkChannel_60000_1000(b *testing.B)  { benchmarkChannel(60000, 1000, b) }
func BenchmarkChannel_70000_1000(b *testing.B)  { benchmarkChannel(70000, 1000, b) }
func BenchmarkChannel_80000_1000(b *testing.B)  { benchmarkChannel(80000, 1000, b) }
func BenchmarkChannel_90000_1000(b *testing.B)  { benchmarkChannel(90000, 1000, b) }
func BenchmarkChannel_100000_1000(b *testing.B) { benchmarkChannel(100000, 1000, b) }

// 2. fix elements, increasing packets
func BenchmarkChannel_100_100000(b *testing.B)    { benchmarkChannel(100, 100000, b) }
func BenchmarkChannel_100_1000000(b *testing.B)   { benchmarkChannel(100, 1000000, b) }
func BenchmarkChannel_100_5000000(b *testing.B)   { benchmarkChannel(100, 5000000, b) }
func BenchmarkChannel_100_10000000(b *testing.B)  { benchmarkChannel(100, 10000000, b) }
func BenchmarkChannel_100_20000000(b *testing.B)  { benchmarkChannel(100, 20000000, b) }
func BenchmarkChannel_100_30000000(b *testing.B)  { benchmarkChannel(100, 30000000, b) }
func BenchmarkChannel_100_40000000(b *testing.B)  { benchmarkChannel(100, 40000000, b) }
func BenchmarkChannel_100_50000000(b *testing.B)  { benchmarkChannel(100, 50000000, b) }
func BenchmarkChannel_100_100000000(b *testing.B) { benchmarkChannel(100, 100000000, b) }

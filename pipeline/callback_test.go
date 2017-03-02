package pipeline

import (
	"testing"
	"sync"
)

var callbackSync sync.WaitGroup = sync.WaitGroup{}

var callbackPacketsize = 200

type CallbackChain struct {
	NextChain *CallbackChain
}

func (c *CallbackChain) run(data *[]byte) {
	if c.NextChain != nil {
		go c.NextChain.run(data);
	} else {
		callbackSync.Done()
	}
}

func benchmarkCallback(length int, packetnum int, b *testing.B) {
	data := make([]byte, callbackPacketsize)

	var last *CallbackChain = &CallbackChain{}
	var first = last
	for i := 1; i < length; i++ {
		last.NextChain = &CallbackChain{}
		last = last.NextChain
	}
	callbackSync.Add(packetnum)
	b.ResetTimer()
	for i := 0; i < packetnum; i++ {
		first.run(&data)
	}
	callbackSync.Wait()
}

// 1. fix packets, increasing elements
func BenchmarkCallback_10000_1000(b *testing.B) {benchmarkCallback(10000, 1000, b)}
func BenchmarkCallback_20000_1000(b *testing.B) {benchmarkCallback(20000, 1000, b)}
func BenchmarkCallback_30000_1000(b *testing.B) {benchmarkCallback(30000, 1000, b)}
func BenchmarkCallback_40000_1000(b *testing.B) {benchmarkCallback(40000, 1000, b)}
func BenchmarkCallback_50000_1000(b *testing.B) {benchmarkCallback(50000, 1000, b)}
func BenchmarkCallback_60000_1000(b *testing.B) {benchmarkCallback(60000, 1000, b)}
func BenchmarkCallback_70000_1000(b *testing.B) {benchmarkCallback(70000, 1000, b)}
func BenchmarkCallback_80000_1000(b *testing.B) {benchmarkCallback(80000, 1000, b)}
func BenchmarkCallback_90000_1000(b *testing.B) {benchmarkCallback(90000, 1000, b)}
func BenchmarkCallback_100000_1000(b *testing.B) {benchmarkCallback(100000, 1000, b)}
func BenchmarkCallback_1000000_1000(b *testing.B) {benchmarkCallback(1000000, 1000, b)}

// 2. fix elements, increasing packets
func BenchmarkCallback_100_10000000(b *testing.B) {benchmarkCallback(100, 10000000, b)}
func BenchmarkCallback_100_20000000(b *testing.B) {benchmarkCallback(100, 20000000, b)}
func BenchmarkCallback_100_30000000(b *testing.B) {benchmarkCallback(100, 30000000, b)}
func BenchmarkCallback_100_40000000(b *testing.B) {benchmarkCallback(100, 40000000, b)}
func BenchmarkCallback_100_50000000(b *testing.B) {benchmarkCallback(100, 50000000, b)}
func BenchmarkCallback_100_100000000(b *testing.B) {benchmarkCallback(100, 100000000, b)}
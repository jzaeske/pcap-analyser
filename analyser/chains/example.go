package chains

import (
	com "../components"
	"github.com/google/gopacket/layers"
	"sync"
)

func GenerateExampleChain() (chain *com.Parser, wg *sync.WaitGroup) {
	wg = &sync.WaitGroup{}
	packets := make(chan com.UnparsedMeasurement, 2000)
	chain = com.NewParser(&packets)
	go chain.Run()
	inputFilter := com.NewFilter(chain, "ether dst 00:0c:29:02:7b:e7")
	go inputFilter.Run()
	counter := com.NewCounter(inputFilter, com.IpCounter{Identifier: "ethIn", Reverse: false}, layers.LayerTypeEthernet)
	go counter.Run()
	counterIp := com.NewCounter(counter, com.IpCounter{Identifier: "ipIn", Reverse: false}, layers.LayerTypeIPv4)
	go counterIp.Run()
	counterTcp := com.NewCounter(counterIp, com.IpCounter{Identifier: "tcpIn", Reverse: false}, layers.LayerTypeTCP)
	go counterTcp.Run()
	synAckFilter := com.NewFilter(counterTcp, "tcp[13] & 0x12 = 18")
	go synAckFilter.Run()
	counterSynAck := com.NewCounter(synAckFilter, com.IpCounter{Identifier: "tcpSynAck", Reverse: false}, layers.LayerTypeTCP)
	go counterSynAck.Run()
	counterNo := com.NewCounterFromFilter(inputFilter, com.IpCounter{Identifier: "ethOut", Reverse: true}, layers.LayerTypeEthernet)
	go counterNo.Run()
	ep := com.NewEndpoint(counterSynAck, wg)
	go ep.Run()
	ep2 := com.NewEndpoint(counterNo, wg)
	go ep2.Run()
	ep3 := com.NewEndpointFromFilter(synAckFilter, wg)
	go ep3.Run()

	return
}

func GenerateExampleStat() (chain *com.Parser, wg *sync.WaitGroup) {
	wg = &sync.WaitGroup{}
	packets := make(chan com.UnparsedMeasurement, 2000)
	chain = com.NewParser(&packets)
	go chain.Run()
	stat := com.NewStat(chain, 0.5)
	go stat.Run()
	ep := com.NewEndpoint(stat, wg)
	go ep.Run()

	return
}

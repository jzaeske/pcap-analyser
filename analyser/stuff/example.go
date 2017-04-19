package stuff

import (
	ch "../chains"
	cl "../classifier"
	com "../components"
	"github.com/google/gopacket/layers"
	"sync"
)

func GenerateExampleChain() (chain *com.Parser, wg *sync.WaitGroup) {
	wg = &sync.WaitGroup{}
	packets := make(chan ch.UnparsedMeasurement, 2000)
	chain = com.NewParser(&packets)
	go chain.Run()
	inputFilter := com.NewFilter(chain, "ether dst 00:0c:29:02:7b:e7")
	go inputFilter.Run()
	counter := com.NewPacketCounter(inputFilter, cl.Ip4Classifier{Identifier: "ethIn", Reverse: false}, layers.LayerTypeEthernet)
	go counter.Run()
	counterIp := com.NewPacketCounter(counter, cl.Ip4Classifier{Identifier: "ipIn", Reverse: false}, layers.LayerTypeIPv4)
	go counterIp.Run()
	counterTcp := com.NewPacketCounter(counterIp, cl.Ip4Classifier{Identifier: "tcpIn", Reverse: false}, layers.LayerTypeTCP)
	go counterTcp.Run()
	synAckFilter := com.NewFilter(counterTcp, "tcp[13] & 0x12 = 18")
	go synAckFilter.Run()
	counterSynAck := com.NewPacketCounter(synAckFilter, cl.Ip4Classifier{Identifier: "tcpSynAck", Reverse: false}, layers.LayerTypeTCP)
	go counterSynAck.Run()
	counterNo := com.NewPacketCounterFromFilter(inputFilter, cl.Ip4Classifier{Identifier: "ethOut", Reverse: true}, layers.LayerTypeEthernet)
	go counterNo.Run()
	ep := com.NewEndpoint(counterSynAck, wg)
	go ep.Run(com.EP_PRIMARY)
	ep2 := com.NewEndpoint(counterNo, wg)
	go ep2.Run(com.EP_PRIMARY)
	ep3 := com.NewEndpoint(synAckFilter, wg)
	go ep3.Run(com.EP_SECONDARY)

	return
}

func GenerateExampleStat() (chain *com.Parser, wg *sync.WaitGroup) {
	wg = &sync.WaitGroup{}
	packets := make(chan ch.UnparsedMeasurement, 2000)
	chain = com.NewParser(&packets)
	go chain.Run()
	stat := com.NewStat(chain, 0.5)
	go stat.Run()
	ep := com.NewEndpoint(stat, wg)
	go ep.Run(com.EP_PRIMARY)

	return
}

func GenerateExampleComposer() (chain *com.Parser, wg *sync.WaitGroup) {
	wg = &sync.WaitGroup{}
	packets := make(chan ch.UnparsedMeasurement, 2000)
	chain = com.NewParser(&packets)
	go chain.Run()
	c := com.NewComposer(chain, false)
	go c.Run()
	tcpCounter := com.NewStreamCounter(c, cl.PortClassifier{Identifier: "stream"})
	go tcpCounter.Run()
	ep := com.NewEndpoint(tcpCounter, wg)
	go ep.Run(com.EP_PRIMARY)
	pc := com.NewPacketCounterFromStreamChain(c, cl.PortClassifier{Identifier: "udp"}, layers.LayerTypeUDP)
	go pc.Run()
	ep2 := com.NewEndpoint(pc, wg)
	go ep2.Run(com.EP_PRIMARY)
	return
}

package chains

import (
	com "../components"
	"sync"
)

func GenerateExampleChain() (chain *com.Parser, wg *sync.WaitGroup) {
	wg = &sync.WaitGroup{}
	packets := make(chan com.UnparsedMeasurement, 2000)
	chain = com.NewParser(&packets)
	go chain.Run()
	inputFilter := com.NewFilter(chain, com.InOutFilter{})
	go inputFilter.Run()
	counter := com.NewCounter(inputFilter, com.DayCounter{Identifier: "ethIn"})
	go counter.Run()
	counterNo := com.NewCounterFromFilter(inputFilter, com.DayCounter{Identifier: "ethOut"})
	go counterNo.Run()
	ep := com.NewEndpoint(counter, wg)
	go ep.Run()
	ep2 := com.NewEndpoint(counterNo, wg)
	go ep2.Run()

	return
}

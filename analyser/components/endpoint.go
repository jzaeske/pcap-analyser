package components

import (
	. "../chains"
	"log"
	"sync"
)

type Endpoint struct {
	empty []func()
	Group *sync.WaitGroup
}

func (e *Endpoint) AddComponent(ch Component) {
	for _, open := range ch.OpenChannels() {
		switch t := open.(type) {
		case *chan TCPStream:
			{
				e.empty = append(e.empty, func() {
					defer e.Group.Done()
					channel := open.(*chan TCPStream)
					for elem := range *channel {
						(func(elem TCPStream) {})(elem)
					}
				})
			}
		case *chan Measurement:
			{
				e.empty = append(e.empty, func() {
					defer e.Group.Done()
					channel := open.(*chan Measurement)
					for elem := range *channel {
						(func(elem Measurement) {})(elem)
					}
				})
			}
		default:
			log.Fatalf("%s is not a valid endpoint channel", t)
		}
	}
}

func (e *Endpoint) Run() {
	if e.empty != nil {
		for _, em := range e.empty {
			e.Group.Add(1)
			go em()
		}
	}
}

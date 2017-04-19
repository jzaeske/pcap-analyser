package components

import (
	. "../chains"
	"log"
	"sync"
)

const (
	EP_PRIMARY   = 0
	EP_SECONDARY = 1
	EP_ALL       = 2
)

type Endpoint struct {
	Id    int `xml:"id,attr"`
	Input chan interface{}
	empty []func()
	group *sync.WaitGroup
}

func NewEndpoint(ch interface{}, group *sync.WaitGroup) (e *Endpoint) {
	ep := &Endpoint{
		group: group,
	}
	switch t := ch.(type) {
	case StreamChain:
		ep.empty = []func(){
			func() {
				defer e.group.Done()
				for elem := range *ch.(StreamChain).Output() {
					(func(elem TCPStream) {})(elem)
				}
			},
			func() {
				defer e.group.Done()
				for elem := range *ch.(StreamChain).Other() {
					(func(elem Measurement) {})(elem)
				}
			},
		}
	case *Filter:
		ep.empty = []func(){
			func() {
				defer e.group.Done()
				for elem := range *ch.(*Filter).Output() {
					(func(elem Measurement) {})(elem)
				}
			},
			func() {
				defer e.group.Done()
				for elem := range *ch.(*Filter).No() {
					(func(elem Measurement) {})(elem)
				}
			},
		}
	case PacketChain:
		ep.empty = []func(){
			func() {
				defer e.group.Done()
				for elem := range *ch.(PacketChain).Output() {
					(func(elem Measurement) {})(elem)
				}
			},
		}
	default:
		log.Println(t)
	}

	return ep
}

func (e *Endpoint) Run(endpointMode int) {
	if e.empty != nil {
		for i, em := range e.empty {
			if i == endpointMode || endpointMode == EP_ALL {
				e.group.Add(1)
				go em()
			}
		}
	}
}

package components

import (
	"sync"
)

type Endpoint struct {
	Id    int `xml:"id,attr"`
	Input chan Measurement
	group *sync.WaitGroup
}

func NewEndpoint(ch Chain, group *sync.WaitGroup) (e *Endpoint) {
	return &Endpoint{
		Input: *ch.Output(),
		group: group,
	}
}

func NewEndpointFromFilter(f *Filter, group *sync.WaitGroup) (e *Endpoint) {
	return &Endpoint{Input: *f.No(), group: group}
}

func (e *Endpoint) Run() {
	e.group.Add(1)
	defer e.group.Done()
	if e.Input != nil {
		for elem := range e.Input {
			// noop
			(func(measurement Measurement) {})(elem)
		}
	}
}

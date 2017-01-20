package report

import (
	"../parser"
	"strconv"
)

type Accumulator struct {
	acc map[string]int
	in  chan string
}

func NewAccumulator(buffer int) (a Accumulator) {
	a.in = make(chan string, buffer)
	a.acc = make(map[string]int)
	return
}

func (a *Accumulator) AddWorker(w *parser.Pcap) {
	w.Acc = a.in
}

func (a *Accumulator) Finish() {
	close(a.in)
}

func (a *Accumulator) Run() {
	for key := range a.in {
		if _, ok := a.acc[key]; ok {
			a.acc[key]++
		} else {
			a.acc[key] = 1
		}
	}
}

func (a *Accumulator) Get(key string) int {
	if count, ok := a.acc[key]; ok {
		return count
	} else {
		return 0
	}
}

func (a *Accumulator) GetCsv() <-chan []string {
	out := make(chan []string)
	go func() {
		for date, count := range a.acc {
			out <- []string{date, strconv.Itoa(count)}
		}
		close(out)
	}()
	return out
}

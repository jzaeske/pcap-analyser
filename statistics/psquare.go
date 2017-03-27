package statistics

import (
	"log"
	"sort"
)

type P2 struct {
	p   float64
	n   uint64
	n_  []int64
	dn  []float64
	q   []float64
	dn_ []float64
}

func NewP2(p float64) *P2 {
	return &P2{
		p:   p,
		n:   0,
		n_:  []int64{1, 2, 3, 4, 5},
		dn:  []float64{1, 1 + 2*p, 1 + 4*p, 3 + 2*p, 5},
		q:   make([]float64, 5),
		dn_: []float64{0, p / 2, p, (1 + p) / 2, 1},
	}
}

func (p *P2) Positions() []int64 {
	return p.n_
}

func (p *P2) Values() []float64 {
	return p.q
}

func (p *P2) Count() uint64 {
	return p.n
}

func (p *P2) AddValue(v float64) {
	p.n++
	if p.n <= 5 {
		// Initialization phase
		p.q[p.n-1] = float64(v)
		if p.n == 5 {
			sort.Float64s(p.q)
		}
	} else {
		k := p.adjustQs(v)
		p.incrementPositionMarkers(k)
		p.adjustHeight()
	}
}

func (p *P2) adjustQs(x float64) int {
	switch {
	case x < p.q[0]:
		p.q[0] = x
		return 0
	case p.q[0] <= x && x < p.q[1]:
		return 0
	case p.q[1] <= x && x < p.q[2]:
		return 1
	case p.q[2] <= x && x < p.q[3]:
		return 2
	case p.q[3] <= x && x <= p.q[4]:
		return 3
	case p.q[4] < x:
		p.q[4] = x
		return 3
	default:
		log.Panicf("cannot find postion for %d in %x", x, p.q)
		return 4
	}
}

func (p *P2) incrementPositionMarkers(k int) {
	for i := k + 1; i < 5; i++ {
		p.n_[i]++
	}
	for i := 0; i < 5; i++ {
		p.dn[i] += p.dn_[i]
	}
}

func sign(x float64) float64 {
	if x < 0 {
		return -1
	}
	return 1
}

func (p *P2) adjustHeight() {
	for i := 1; i < 4; i++ {
		d := p.dn[i] - float64(p.n_[i])
		if (d >= 1 && p.n_[i+1]-p.n_[i] > 1) || (d <= -1 && p.n_[i-1]-p.n_[i] < -1) {
			d = sign(d)
			q := p.parabol(i, d)
			if p.q[i-1] < q && q < p.q[i+1] {
				p.q[i] = q
			} else {
				p.q[i] = p.q[i] + d*((p.q[i+int(d)]-p.q[i])/(float64(p.n_[i+int(d)])-float64(p.n_[i])))
			}
			p.n_[i] += int64(d)
		}
	}
}

func (p *P2) parabol(i int, d float64) float64 {
	return p.q[i] + (d/(float64(p.n_[i+1])-float64(p.n_[i-1])))*((float64(p.n_[i])-float64(p.n_[i-1])+d)*(p.q[i+1]-p.q[i])/(float64(p.n_[i+1])-float64(p.n_[i]))+(float64(p.n_[i+1])-float64(p.n_[i])-d)*(p.q[i]-p.q[i-1])/(float64(p.n_[i])-float64(p.n_[i-1])))
}

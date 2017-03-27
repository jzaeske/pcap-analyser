package statistics

type Mean struct {
	count uint64
	sum   float64
}

func NewMean() *Mean {
	return &Mean{
		count: 0,
		sum:   0,
	}
}

func (m *Mean) AddFloat(value float64) {
	m.count++
	m.sum += value
}

func (m *Mean) AddInt(value int) {
	m.AddFloat(float64(value))
}

func (m *Mean) Mean() float64 {
	if m.count > 0 {
		return m.sum / float64(m.count)
	}
	return 0
}

package components

type Filter struct {
	criteria FilterCriteria
	input    chan Measurement
	output   chan Measurement
	no       chan Measurement
}

func NewFilter(ch Chain, criteria FilterCriteria) (f *Filter) {
	return &Filter{
		criteria: criteria,
		input:    *ch.Output(),
		output:   make(chan Measurement, 2000),
		no:       make(chan Measurement, 2000),
	}
}

func (f *Filter) Output() *chan Measurement {
	return &f.output
}

func (f *Filter) No() *chan Measurement {
	return &f.no
}

func (f *Filter) Run() {
	defer close(f.output)
	defer close(f.no)
	if f.input != nil {
		for measurement := range f.input {
			if f.criteria.Decide(measurement) {
				f.output <- measurement
			} else {
				f.no <- measurement
			}
		}
	}
}

package statistics_test

import (
	"github.com/jzaeske/pcap-analyser/statistics"
	"testing"
)

var meanTests = []struct {
	n        []float64 // input
	expected float64   // expected result
}{
	{[]float64{1, 2, 3, 4}, 2.5},
	{[]float64{}, 0},
	{[]float64{300, 500, 1032, 4566, 182}, 1316},
}

func TestMean_AddFloat(t *testing.T) {
	m := statistics.NewMean()
	m.AddFloat(61.)
}

func TestMean_AddInt(t *testing.T) {
	m := statistics.NewMean()
	m.AddInt(10)
}

func TestMean_Mean(t *testing.T) {
	for _, tt := range meanTests {
		m := statistics.NewMean()
		for _, value := range tt.n {
			m.AddFloat(value)
		}
		actual := m.Mean()
		if actual != tt.expected {
			t.Errorf("Mean expected %d, actual %d", tt.expected, actual)
		}
	}
}

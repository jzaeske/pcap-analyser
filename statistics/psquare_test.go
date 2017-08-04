package statistics_test

import (
	"fmt"
	"github.com/jzaeske/pcap-analyser/statistics"
	"math"
	"testing"
)

// Testing P^2 Algorithms implementation against the example in Ray Jain's Paper about P^2

var values = []float64{
	// initialization
	0.02, 0.15, 0.74, 3.39, 0.83,
	// test values
	22.37, 10.15, 15.43, 38.62, 15.92,
	34.60, 10.28, 1.47, 0.40, 0.05,
	11.39, 0.27, 0.42, 0.09, 11.37,
}

var expectedHeights = [][]float64{
	{0.02, 0.15, 0.74, 0.83, 22.37},  // 6
	{0.02, 0.15, 0.74, 4.47, 22.37},  // 7
	{0.02, 0.15, 2.18, 8.60, 22.37},  // 8
	{0.02, 0.87, 4.75, 15.52, 38.62}, // 9
	{0.02, 0.87, 4.75, 15.52, 38.62}, // 10
	{0.02, 0.87, 9.28, 21.58, 38.62}, // 11
	{0.02, 0.87, 9.28, 21.58, 38.62}, // 12
	{0.02, 2.14, 9.28, 21.58, 38.62}, // 13
	{0.02, 2.14, 9.28, 21.58, 38.62}, // 14
	{0.02, 0.74, 6.30, 21.58, 38.62}, // 15
	{0.02, 0.74, 6.30, 21.58, 38.62}, // 16
	{0.02, 0.59, 6.30, 17.22, 38.62}, // 17
	{0.02, 0.59, 6.30, 17.22, 38.62}, // 18
	{0.02, 0.50, 4.44, 17.22, 38.62}, // 19
	{0.02, 0.50, 4.44, 17.22, 38.62}, // 20
}

var expectedPositions = [][]int64{
	{1, 2, 3, 4, 6},
	{1, 2, 3, 5, 7},
	{1, 2, 4, 6, 8},
	{1, 3, 5, 7, 9},
	{1, 3, 5, 7, 10},
	{1, 3, 6, 8, 11},
	{1, 3, 6, 9, 12},
	{1, 4, 7, 10, 13},
	{1, 5, 8, 11, 14},
	{1, 5, 8, 12, 15},
	{1, 5, 8, 13, 16},
	{1, 5, 9, 13, 17},
	{1, 6, 10, 14, 18},
	{1, 6, 10, 15, 19},
	{1, 6, 10, 16, 20},
}

// Genauigkeit der Referenzwerte
var EPSILON = 0.017

func compare(actual float64, expected float64) bool {
	return math.Abs(actual-expected) < EPSILON
}

func TestP2_Values(t *testing.T) {
	p2 := statistics.NewP2(0.5)

	for i, value := range values {
		p2.AddValue(value)
		// only test after initialization
		if i >= 5 {
			expected := expectedHeights[i-5]
			actual := p2.Values()
			for j, act := range actual {

				if compare(act, expected[j]) == false {
					fmt.Println(actual)
					fmt.Println(expected)
					t.Errorf("height not corrent value #%d, marker %d has height %f, expecting %f", i, j, act, expected[j])
				}
			}
		}
	}
}

func TestP2_Count(t *testing.T) {
	p2 := statistics.NewP2(0.5)

	for _, value := range values {
		p2.AddValue(value)
	}

	if p2.Count() != uint64(len(values)) {
		t.Errorf("wrong count %d, expecting %d", p2.Count(), len(values))
	}
}

func TestP2_Positions(t *testing.T) {
	p2 := statistics.NewP2(0.5)

	for i, value := range values {
		p2.AddValue(value)
		// only test after initialization
		if i >= 5 {
			expectedPosition := expectedPositions[i-5]
			actualPosition := p2.Positions()
			for j, act := range actualPosition {
				if act != expectedPosition[j] {
					fmt.Println(actualPosition)
					fmt.Println(expectedPosition)
					t.Errorf("marker not corrent value #%d, marker %d has position %d, expecting %d", i, j, act, expectedPosition[j])
				}
			}
		}
	}
}

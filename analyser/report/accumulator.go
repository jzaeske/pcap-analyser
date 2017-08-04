package report

import (
	"github.com/jzaeske/pcap-analyser/merge"
	"sort"
	"strconv"
	"sync"
	"time"
)

var accumulators map[string][]Accumulator

var accumulatorLock sync.RWMutex

type (
	Accumulator struct {
		acc        map[string]map[string]int
		identifier string
	}
)

func GenerateAccumulator(identifier string) *Accumulator {
	accumulatorLock.Lock()
	if accumulators == nil {
		accumulators = make(map[string][]Accumulator)
	}

	accumulator := newAccumulator(identifier)
	if accs, ok := accumulators[identifier]; ok {
		accumulators[identifier] = append(accs, accumulator)
	} else {
		accumulators[identifier] = []Accumulator{accumulator}
	}
	accumulatorLock.Unlock()
	return &accumulator
}

func GetJoinedAccumulator(identifier string) Accumulator {
	if accs, ok := accumulators[identifier]; ok {
		result := accs[0]
		for i, acc := range accs {
			if i == 0 {
				continue
			}
			result.Merge(acc)
		}
		return result
	}
	return newAccumulator(identifier)
}

func GetIdentifiers() []string {
	var identifers []string
	for ident := range accumulators {
		identifers = append(identifers, ident)
	}
	return identifers
}

func newAccumulator(identifier string) (a Accumulator) {
	a.acc = make(map[string]map[string]int)
	a.identifier = identifier
	return
}

func (a *Accumulator) Merge(other Accumulator) {
	merge.Map2StringInt(&a.acc, &other.acc)
}

func (a *Accumulator) Increment(row string, column string) {
	a.IncrementValue(row, column, 1)
}

func (a *Accumulator) IncrementValue(row string, column string, value int) {
	if _, ok := a.acc[row]; ok {
		if _, ok2 := a.acc[row][column]; ok2 {
			a.acc[row][column] += value
		} else {
			a.acc[row][column] = value
		}
	} else {
		rowMap := make(map[string]int)
		rowMap[column] = value
		a.acc[row] = rowMap
	}
}

func (a *Accumulator) SetValue(row string, column string, value int) {
	if _, ok := a.acc[row]; ok {
		a.acc[row][column] = value
	} else {
		rowMap := make(map[string]int)
		rowMap[column] = value
		a.acc[row] = rowMap
	}
}

func (a *Accumulator) Columns() (columns []string) {
	colMap := make(map[string]bool)
	for _, row := range a.acc {
		for column := range row {
			colMap[column] = true
		}
	}
	columns = make([]string, len(colMap))
	iterator := 0
	for key := range colMap {
		columns[iterator] = key
		iterator++
	}
	return
}

func (a *Accumulator) Get(row string, column string) int {
	if _, ok := a.acc[row]; ok {
		if _, ok2 := a.acc[row][column]; ok2 {
			return a.acc[row][column]
		}
	}
	return 0

}

func (a *Accumulator) GetCsv() <-chan []string {
	out := make(chan []string)
	go func() {
		// Header Row with column names
		columns := a.Columns()
		sort.Strings(columns)
		out <- append([]string{a.identifier}, columns...)
		for date, row := range a.acc {
			rowData := []string{date}
			for _, column := range columns {
				if len(column) > 3 && column[0:4] == "date" {
					date := time.Unix(int64(row[column]), 0)
					rowData = append(rowData, date.Format("2006/01/02 15:04:05"))
				} else {
					rowData = append(rowData, strconv.Itoa(row[column]))
				}
			}
			out <- rowData
		}
		close(out)
	}()
	return out
}

func (a *Accumulator) Summary() map[string]int {
	summary := make(map[string]int)
	for _, key := range a.Columns() {
		value := 0
		for date := range a.acc {
			value += a.Get(date, key)
		}
		summary[key] = value
	}
	return summary
}

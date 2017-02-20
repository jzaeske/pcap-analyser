package report

import (
	"../../merge"
	"strconv"
	"time"
)

type Accumulator struct {
	acc     map[string]map[string]int
	columns []string
}

func NewAccumulator(columns []string) (a Accumulator) {
	a.acc = make(map[string]map[string]int)
	a.columns = columns
	return
}

func (a *Accumulator) Merge(other Accumulator) {
	merge.MergeMap2StringInt(&a.acc, &other.acc)
}

func (a *Accumulator) Increment(row string, column string) {
	a.IncrementValue(row, column, 1)
}

func (a *Accumulator) IncrementValue(row string, column string, value int) {
	if _, ok := a.acc[row]; ok {
		if _, ok2 := a.acc[row][column]; ok2 {
			a.acc[row][column] += value
		}
	} else {
		rowMap := make(map[string]int)
		for _, columnName := range a.columns {
			rowMap[columnName] = 0
		}
		rowMap[column] += value
		a.acc[row] = rowMap
	}
}

func (a *Accumulator) SetValue(row string, column string, value int) {
	if _, ok := a.acc[row]; ok {
		a.acc[row][column] = value
	} else {
		rowMap := make(map[string]int)
		for _, columnName := range a.columns {
			rowMap[columnName] = 0
		}
		rowMap[column] = value
		a.acc[row] = rowMap
	}
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
		out <- append([]string{"date"}, a.columns...)
		for date, row := range a.acc {
			rowData := []string{date}
			for _, column := range a.columns {
				if column[0:4] == "date" {
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
	for _, key := range a.columns {
		value := 0
		for date := range a.acc {
			value += a.Get(date, key)
		}
		summary[key] = value
	}
	return summary
}

package merge

func Map2StringInt(dst *map[string]map[string]int, src *map[string]map[string]int) {
	for rowIdentifier, srcRow := range *src {
		if dstRow, ok := (*dst)[rowIdentifier]; ok {
			MapStringInt(&dstRow, &srcRow)
		} else {
			(*dst)[rowIdentifier] = srcRow
		}
	}
}

func MapStringInt(dst *map[string]int, src *map[string]int) {
	for columnIdentifier, value := range *src {
		if _, ok := (*dst)[columnIdentifier]; ok {
			(*dst)[columnIdentifier] += value
		} else {
			(*dst)[columnIdentifier] = value
		}
	}
}

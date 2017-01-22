package merge

func MergeMap2StringInt (dst *map[string]map[string]int, src *map[string]map[string]int) {
	for rowIdentifier, srcRow := range (*src) {
		if dstRow, ok := (*dst)[rowIdentifier]; ok {
			MergeMapStringInt(&dstRow, &srcRow)
		} else {
			(*dst)[rowIdentifier] = srcRow
		}
	}
}

func MergeMapStringInt (dst *map[string]int, src *map[string]int) {
	for columnIdentifier, value := range (*src) {
		if _, ok := (*dst)[columnIdentifier]; ok {
			(*dst)[columnIdentifier] += value
		} else {
			(*dst)[columnIdentifier] = value
		}
	}
}
package merge

import (
	"log"
	"reflect"
	"testing"
)

func TestMergeMapStringInt(t *testing.T) {
	dst := map[string]int{"a": 2, "b": 3}
	src := map[string]int{"b": 2, "c": 4}
	expected := map[string]int{"a": 2, "b": 5, "c": 4}
	MapStringInt(&dst, &src)

	if !reflect.DeepEqual(dst, expected) {
		log.Fatalf("Expected %x to be %x", dst, expected)
		t.Fail()
	}
}

func TestMergeMap2StringInt(t *testing.T) {
	dst := map[string]map[string]int{
		"a": {"b": 1, "c": 2},
		"d": {"e": 3},
	}
	src := map[string]map[string]int{
		"a": {"b": 2},
		"d": {"e": 4},
		"b": {"a": 1},
	}
	expected := map[string]map[string]int{
		"a": {"b": 3, "c": 2},
		"d": {"e": 7},
		"b": {"a": 1},
	}

	Map2StringInt(&dst, &src)
	if !reflect.DeepEqual(dst, expected) {
		log.Fatalf("Expected %x to be %x", dst, expected)
		t.Fail()
	}
}

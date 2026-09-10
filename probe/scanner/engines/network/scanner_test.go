package main

import (
	"reflect"
	"testing"
)

func TestParsePortsResolvesRangesAndDeduplicates(t *testing.T) {
	got := parsePorts("80,443,8000-8002,443")
	want := []int{80, 443, 8000, 8001, 8002}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parsePorts() = %v, want %v", got, want)
	}
}

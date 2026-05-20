package main

import (
	"encoding/csv"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type sampleSet []float64

func (s sampleSet) mean() float64 {
	if len(s) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range s {
		sum += v
	}
	return sum / float64(len(s))
}

func (s sampleSet) median() float64 {
	if len(s) == 0 {
		return 0
	}
	cp := append([]float64(nil), s...)
	sort.Float64s(cp)
	mid := len(cp) / 2
	if len(cp)%2 == 1 {
		return cp[mid]
	}
	return (cp[mid-1] + cp[mid]) / 2
}

func (s sampleSet) stddev() float64 {
	if len(s) < 2 {
		return 0
	}
	mean := s.mean()
	sum := 0.0
	for _, v := range s {
		d := v - mean
		sum += d * d
	}
	return math.Sqrt(sum / float64(len(s)-1))
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: go run REG/stats/main.go REG/results/*.csv")
		os.Exit(2)
	}

	for _, path := range os.Args[1:] {
		if strings.Contains(path, "_both") {
			continue
		}
		if err := summarize(path); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
			os.Exit(1)
		}
	}
}

func summarize(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		return err
	}
	if len(records) < 2 {
		return nil
	}

	header := make(map[string]int)
	for i, name := range records[0] {
		header[name] = i
	}

	fields := []string{"metadata_guard_ns", "local_total_ns", "cert_online_ns", "cert_full_ns", "total_ns", "exact_rank_audit_ns"}
	values := make(map[string]sampleSet)
	accepted := 0
	rows := 0
	for _, rec := range records[1:] {
		if len(rec) == 0 {
			continue
		}
		op := rec[0]
		if op != "WIncrease" && op != "WDecrease" && op != "TIncrease" && op != "TDecrease" {
			continue
		}
		rows++
		if rec[header["accepted"]] == "true" {
			accepted++
		}
		for _, field := range fields {
			idx, ok := header[field]
			if !ok || idx >= len(rec) {
				continue
			}
			ns, err := strconv.ParseFloat(rec[idx], 64)
			if err != nil {
				return err
			}
			values[field] = append(values[field], ns/1_000_000)
		}
	}

	fmt.Printf("%s rows=%d accepted=%d\n", filepath.Base(path), rows, accepted)
	for _, field := range fields {
		set := values[field]
		if len(set) == 0 {
			continue
		}
		unit := "ms"
		scale := 1.0
		if field == "metadata_guard_ns" || field == "exact_rank_audit_ns" {
			unit = "us"
			scale = 1000.0
		}
		fmt.Printf("  %s mean=%.3f%s median=%.3f%s stddev=%.3f%s\n",
			field, set.mean()*scale, unit, set.median()*scale, unit, set.stddev()*scale, unit)
	}
	return nil
}

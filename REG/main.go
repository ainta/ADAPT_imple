package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	. "ADAPT_FROST/ADAPT/algorithm"
)

func main() {
	repeats := flag.Int("repeats", 5, "number of benchmark repetitions")
	target := flag.Int("target", 0, "weight-update target and corrupted owner")
	staleTTL := flag.Int("stale-ttl", 2, "epochs before stale rows expire")
	certMode := flag.String("cert", "none", "certificate mode: none, online, full, both")
	runLocal := flag.Bool("local", true, "run the underlying ADAPT local update routine")
	sequenceMode := flag.Bool("sequence", false, "run operations against one evolving REG state")
	auditExact := flag.Bool("audit-exact", false, "compute exact finite-field rank audit columns")
	auditPointOffset := flag.Int("audit-point-offset", 0, "coordinate offset for exact rank audit rows; 0 matches the public ADAPT artifact")
	opList := flag.String("ops", "WIncrease,TIncrease,WDecrease,TDecrease", "comma-separated operations")
	prefixSet := flag.Bool("prefix-threshold-set", true, "force a deterministic prefix threshold set")
	attackDemo := flag.Bool("attack-demo", true, "print a metadata-only REG rejection demo for the ADAPT sequence")
	tightnessDemo := flag.Bool("tightness-demo", true, "print a conservative-vs-exact rank tightness demo")

	flag.CommandLine.Parse(os.Args[3:])
	REGSetAuditPointOffset(*auditPointOffset)

	if *prefixSet && !REGForcePrefixThresholdSet() {
		fmt.Fprintln(os.Stderr, "warning: could not force prefix threshold set exactly matching threshold")
	}

	setupStart := time.Now()
	Round1()
	Round2()
	Preprocessing()
	setupTime := time.Since(setupStart)

	fmt.Printf("# REG-ADAPT benchmark\n")
	fmt.Printf("# args_N=%s args_threshold=%s setup_ns=%d repeats=%d target=%d cert=%s local=%t stale_ttl=%d sequence=%t audit_exact=%t audit_point_offset=%d\n",
		os.Args[1], os.Args[2], setupTime.Nanoseconds(), *repeats, *target, *certMode, *runLocal, *staleTTL, *sequenceMode, *auditExact, *auditPointOffset)

	if *attackDemo {
		printAttackDemo(*staleTTL)
	}
	if *tightnessDemo {
		printTightnessDemo()
	}

	ops := parseOps(*opList)
	fmt.Println(REGCSVHeader())
	for r := 0; r < *repeats; r++ {
		state := REGNewState([]int{*target}, *staleTTL)
		state.PointOffset = *auditPointOffset
		state.AuditExact = *auditExact
		for _, op := range ops {
			if !*sequenceMode {
				state = REGNewState([]int{*target}, *staleTTL)
				state.PointOffset = *auditPointOffset
				state.AuditExact = *auditExact
			}
			metrics := state.Apply(op, *target, 1, *certMode, *runLocal)
			fmt.Println(metrics.CSVRow())
		}
	}
}

func printTightnessDemo() {
	m := REGExactRankTightnessExample()
	fmt.Printf("# exact-rank tightness demo threshold=%d conservative_final=%d exact_final=%d conservative_rejects=%t exact_accepts=%t\n",
		m.Threshold, m.ConservativeFinalRank, m.ExactFinalRank, m.ConservativeRejects, m.ExactAccepts)
}

func parseOps(raw string) []REGOperation {
	parts := strings.Split(raw, ",")
	ops := make([]REGOperation, 0, len(parts))
	for _, part := range parts {
		switch strings.TrimSpace(strings.ToLower(part)) {
		case "wincrease", "winc":
			ops = append(ops, REGWIncrease)
		case "wdecrease", "wdec":
			ops = append(ops, REGWDecrease)
		case "tincrease", "tinc":
			ops = append(ops, REGTIncrease)
		case "tdecrease", "tdec":
			ops = append(ops, REGTDecrease)
		case "":
		default:
			fmt.Fprintln(os.Stderr, "unknown op:", part)
			os.Exit(2)
		}
	}
	return ops
}

func printAttackDemo(staleTTL int) {
	state := REGSyntheticState(100, []int{99, 101}, []int{0}, staleTTL)
	state.AuditExact = true
	seq := []struct {
		op     REGOperation
		target int
		delta  int
	}{
		{REGTIncrease, 0, 50},
		{REGWIncrease, 0, 50},
		{REGTDecrease, 0, 50},
	}

	fmt.Println("# ADAPT-style sequence demo under REG metadata guard")
	for i, step := range seq {
		m := state.Apply(step.op, step.target, step.delta, "none", false)
		fmt.Printf("# demo_step=%d op=%s delta=%d accepted=%t old_t=%d new_t=%d final_exposure=%d transient_exposure=%d reason=%s\n",
			i+1, step.op, step.delta, m.Accepted, m.OldThreshold, m.NewThreshold,
			m.FinalExposure, m.TransientExposure, strconv.Quote(m.Reason))
	}
}

// Command bench splits `failopen audit --snapshot` into its phases for one
// snapshot file: JSON load, detector.Run (repeated, median reported) and
// terminal rendering. Prints one JSON line.
//
//	go run ./hack/experiments/exp5/bench -snapshot snap-1000.json -runs 5
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/pprof"
	"slices"
	"time"

	"github.com/kkattl/failopen/internal/collector"
	"github.com/kkattl/failopen/internal/detector"
	"github.com/kkattl/failopen/internal/report"
)

func median(d []time.Duration) time.Duration {
	s := slices.Clone(d)
	slices.Sort(s)
	return s[len(s)/2]
}

func main() {
	path := flag.String("snapshot", "", "snapshot JSON")
	runs := flag.Int("runs", 5, "repetitions per phase")
	cpuprof := flag.String("cpuprofile", "", "write a CPU profile of the detector phase here")
	flag.Parse()

	var loads, detects, renders []time.Duration
	var snap *collector.Snapshot
	for range *runs {
		f, err := os.Open(*path)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		t := time.Now()
		snap, err = collector.ReadJSON(f)
		loads = append(loads, time.Since(t))
		f.Close()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	// Per-detector timings too (profiled together with detector.Run).
	perDet := map[string]time.Duration{}
	var findings []detector.Finding
	if *cpuprof != "" {
		pf, err := os.Create(*cpuprof)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		pprof.StartCPUProfile(pf)
		defer pprof.StopCPUProfile()
	}
	for range *runs {
		t := time.Now()
		findings = detector.Run(snap)
		detects = append(detects, time.Since(t))
	}
	for _, d := range detector.All() {
		var ds []time.Duration
		for range *runs {
			t := time.Now()
			d.Detect(snap)
			ds = append(ds, time.Since(t))
		}
		perDet[d.Name()] = median(ds)
	}
	for range *runs {
		t := time.Now()
		report.Terminal(io.Discard, findings, snap, report.Options{Width: 100})
		renders = append(renders, time.Since(t))
	}
	sev := map[detector.Severity]int{}
	for _, f := range findings {
		sev[f.Severity]++
	}
	ms := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
	out := map[string]any{
		"pods": len(snap.Pods), "services": len(snap.Services), "policies": len(snap.NetworkPolicies),
		"namespaces": len(snap.Namespaces), "nodes": len(snap.Nodes),
		"load_ms": ms(median(loads)), "detect_ms": ms(median(detects)), "render_ms": ms(median(renders)),
		"findings": len(findings), "critical": sev[detector.SeverityCritical], "warning": sev[detector.SeverityWarning],
	}
	for k, v := range perDet {
		out["detect_"+k+"_ms"] = ms(v)
	}
	json.NewEncoder(os.Stdout).Encode(out)
}

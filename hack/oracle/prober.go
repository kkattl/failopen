package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kkattl/failopen/internal/scenario"
)

// probeParallelism caps concurrent connects inside one source pod.
const probeParallelism = 4

type prober struct {
	kube    *kube
	timeout time.Duration

	mu       sync.Mutex
	failures []string // sources whose exec failed; results would be garbage
}

// probeAll runs every applicable probe; one exec per source fans out all
// of that source's connections in parallel inside the pod.
func (p *prober) probeAll(ctx context.Context, sources []source, targets []target) map[pair]string {
	results := map[pair]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)

	for si, src := range sources {
		var idx []int
		for ti, t := range targets {
			if applicable(src, t) {
				idx = append(idx, ti)
			}
		}
		if len(idx) == 0 {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(si int, src source, idx []int) {
			defer wg.Done()
			defer func() { <-sem }()
			got := p.probeFrom(ctx, src, targets, idx)
			mu.Lock()
			defer mu.Unlock()
			for ti, r := range got {
				results[pair{si, ti}] = r
			}
		}(si, src, idx)
	}
	wg.Wait()
	return results
}

func (p *prober) probeFrom(ctx context.Context, src source, targets []target, idx []int) map[int]string {
	out := map[int]string{}
	if src.Kind == scenario.SourceExternal {
		for _, ti := range idx {
			out[ti] = p.dial(targets[ti].Address)
		}
		return out
	}

	var addrs []string
	byAddr := map[string]int{}
	for _, ti := range idx {
		addrs = append(addrs, targets[ti].Address)
		byAddr[targets[ti].Address] = ti
	}
	secs := max(1, int(p.timeout.Seconds()))
	// Batches of probeParallelism: every agnhost process lives in the
	// source pod's cgroup, and scenario pods often have tight memory limits
	// (33 concurrent connects OOM-killed a 64Mi pod).
	var script strings.Builder
	for i := 0; i < len(addrs); i += probeParallelism {
		for _, a := range addrs[i:min(i+probeParallelism, len(addrs))] {
			fmt.Fprintf(&script, `( r=$(/agnhost connect %s --timeout=%ds 2>&1); if [ $? -eq 0 ]; then echo "%s OPEN"; else echo "%s $(echo $r)"; fi ) & `, a, secs, a, a)
		}
		script.WriteString("wait\n")
	}
	stdout, err := p.kube.exec(ctx, src.Pod, src.Container, []string{"sh", "-c", script.String()})
	if err != nil {
		logf("exec from %s failed: %v", src.Name, err)
		p.mu.Lock()
		p.failures = append(p.failures, src.Name)
		p.mu.Unlock()
	}
	for _, line := range strings.Split(stdout, "\n") {
		addr, rest, ok := strings.Cut(strings.TrimSpace(line), " ")
		if ti, known := byAddr[addr]; ok && known {
			out[ti] = classifyOutput(rest)
		}
	}
	for _, ti := range idx {
		if _, ok := out[ti]; !ok {
			out[ti] = scenario.EffectiveError
		}
	}
	return out
}

func classifyOutput(s string) string {
	switch {
	case strings.Contains(s, "OPEN"):
		return scenario.EffectiveOpen
	case strings.Contains(s, "REFUSED"):
		return scenario.EffectiveRefused
	case strings.Contains(s, "TIMEOUT"):
		return scenario.EffectiveTimeout
	default:
		return scenario.EffectiveError
	}
}

// dial probes from the machine running the oracle ("external").
func (p *prober) dial(addr string) string {
	conn, err := net.DialTimeout("tcp", addr, p.timeout)
	if err == nil {
		conn.Close()
		return scenario.EffectiveOpen
	}
	var ne net.Error
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return scenario.EffectiveRefused
	case errors.As(err, &ne) && ne.Timeout():
		return scenario.EffectiveTimeout
	default:
		return scenario.EffectiveError
	}
}

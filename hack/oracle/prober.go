package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kkattl/failopen/internal/scenario"
)

// job is one thing a source does: a TCP connect, or an HTTP GET of
// /clientip to learn which source address the target saw.
type job struct {
	key      string
	addr     string
	identity bool
}

type prober struct {
	kube    *kube
	timeout time.Duration
	// extContainer, if set, is a docker container that sources "external"
	// probes (hack/lab/external.sh); otherwise the oracle host dials itself.
	extContainer string
	// parallelism caps concurrent connects inside one source pod. Ephemeral
	// containers have no limits of their own: they share the pod cgroup with
	// the app, and a 64Mi pod OOMs with 4 concurrent agnhost processes.
	parallelism int

	mu       sync.Mutex
	failures []string // sources whose exec failed; results would be garbage
}

// run executes every source's jobs (sources in parallel, jobs batched inside
// each source) and returns raw results: source index -> job key -> output.
func (p *prober) run(ctx context.Context, sources []source, plan map[int][]job) map[int]map[string]string {
	results := map[int]map[string]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for si, jobs := range plan {
		if len(jobs) == 0 {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(si int, jobs []job) {
			defer wg.Done()
			defer func() { <-sem }()
			got := p.runFrom(ctx, sources[si], jobs)
			mu.Lock()
			results[si] = got
			mu.Unlock()
		}(si, jobs)
	}
	wg.Wait()
	return results
}

func (p *prober) runFrom(ctx context.Context, src source, jobs []job) map[string]string {
	out := map[string]string{}
	if src.Kind == scenario.SourceExternal && p.extContainer == "" {
		for _, j := range jobs {
			if !j.identity {
				out[j.key] = p.dial(j.addr)
			}
		}
		return out
	}
	script := p.script(jobs)
	var stdout string
	var err error
	if src.Kind == scenario.SourceExternal {
		var b []byte
		b, err = exec.CommandContext(ctx, "docker", "exec", p.extContainer, "sh", "-c", script).Output()
		stdout = string(b)
	} else {
		stdout, err = p.kube.exec(ctx, src.Pod, src.Container, []string{"sh", "-c", script})
	}
	if err != nil {
		logf("exec from %s failed: %v", src.Name, err)
		p.mu.Lock()
		p.failures = append(p.failures, src.Name)
		p.mu.Unlock()
	}
	for _, line := range strings.Split(stdout, "\n") {
		if key, rest, ok := strings.Cut(strings.TrimSpace(line), " "); ok {
			out[key] = rest
		}
	}
	return out
}

// script runs the jobs in batches of p.parallelism. A connect that times out
// is retried once before it counts: one lost SYN must not become a verdict.
func (p *prober) script(jobs []job) string {
	secs := max(1, int(p.timeout.Seconds()))
	var b strings.Builder
	for i := 0; i < len(jobs); i += p.parallelism {
		for _, j := range jobs[i:min(i+p.parallelism, len(jobs))] {
			if j.identity {
				fmt.Fprintf(&b, `( echo "%s $(wget -q -O- -T %d http://%s/clientip 2>/dev/null || echo FAIL)" ) & `, j.key, secs, j.addr)
				continue
			}
			fmt.Fprintf(&b, `( c() { /agnhost connect %s --timeout=%ds 2>&1; }; r=$(c); rc=$?; `+
				`if [ $rc -ne 0 ] && echo "$r" | grep -q TIMEOUT; then r=$(c); rc=$?; fi; `+
				`if [ $rc -eq 0 ]; then echo "%s OPEN"; else echo "%s $(echo $r)"; fi ) & `,
				j.addr, secs, j.key, j.key)
		}
		b.WriteString("wait\n")
	}
	return b.String()
}

// classifyOutput maps agnhost connect output to an Effective* constant.
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

// parseClientIP extracts the address from a /clientip answer ("ip:port").
func parseClientIP(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s == "FAIL" {
		return "", false
	}
	host, _, ok := cutHostPort(s)
	if !ok || net.ParseIP(strings.Trim(host, "[]")) == nil {
		return "", false
	}
	return strings.Trim(host, "[]"), true
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

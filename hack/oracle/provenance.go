package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kkattl/failopen/internal/collector"
	"github.com/kkattl/failopen/internal/scenario"
)

// npaDir is where `make oracle-deps` checks out policy-assistant.
const npaDir = "hack/oracle/.deps/network-policy-api"

func (k *kube) provenance(ctx context.Context, cfg config, snap *collector.Snapshot, outsider string) *scenario.Provenance {
	p := &scenario.Provenance{
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
		OracleCommit:    gitDescribe("."),
		PolicyAssistant: gitDescribe(npaDir),
		OutsiderNode:    outsider,
		ProbeTimeout:    cfg.probeTimeout.String(),
		ServiceAttempts: cfg.serviceAttempts,
	}
	if data, err := os.ReadFile(cfg.manifests); err == nil {
		sum := sha256.Sum256(data)
		p.ManifestSHA256 = hex.EncodeToString(sum[:])
	}
	if len(snap.Nodes) > 0 {
		info := snap.Nodes[0].Status.NodeInfo
		p.KubeletVersion, p.ContainerRuntime = info.KubeletVersion, info.ContainerRuntimeVersion
	}
	if ds, err := k.cs.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{}); err == nil {
		for _, d := range ds.Items {
			if !systemNamespaces.MatchString(d.Namespace) {
				continue
			}
			for _, c := range d.Spec.Template.Spec.Containers {
				p.CNIImages = append(p.CNIImages, c.Image)
			}
		}
		slices.Sort(p.CNIImages)
		p.CNIImages = slices.Compact(p.CNIImages)
	}
	return p
}

// gitDescribe returns HEAD of the repo at dir, "-dirty" if it has changes.
func gitDescribe(dir string) string {
	head, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		return "unknown"
	}
	out := strings.TrimSpace(string(head))
	if status, err := exec.Command("git", "-C", dir, "status", "--porcelain").Output(); err == nil && len(status) > 0 {
		out += "-dirty"
	}
	return out
}

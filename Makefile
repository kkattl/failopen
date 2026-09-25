CLUSTER    := failopen-demo
KUBECONFIG := $(CURDIR)/hack/demo/kubeconfig
KCTL       := kubectl --kubeconfig=$(KUBECONFIG)
CALICO_VER := v3.28.0
# policy-assistant (NetworkPolicy matcher) pinned for the oracle.
NPA_SHA    := 318a5176525c3dff6e5c406cb8f745506b73194e
NPA_DIR    := hack/oracle/.deps/network-policy-api

.PHONY: demo audit demo-down build lab lab-down matrix oracle-deps oracle scenario corpus-summary

demo:
	kind create cluster --name $(CLUSTER) \
		--config hack/demo/kind-config.yaml \
		--kubeconfig $(KUBECONFIG)
	$(KCTL) apply -f https://raw.githubusercontent.com/projectcalico/calico/$(CALICO_VER)/manifests/calico.yaml
	$(KCTL) -n kube-system rollout status ds/calico-node --timeout=180s
	$(KCTL) apply -f testdata/scenarios/demo-payments/manifests.yaml
	@echo "demo cluster ready. run: make audit"

audit: build
	./bin/failopen audit --kubeconfig $(KUBECONFIG)

build:
	go build -o bin/failopen ./cmd/failopen

demo-down:
	kind delete cluster --name $(CLUSTER)

# --- lab clusters: production-shaped (pools, taints, zones), one per CNI ---
# Profiles live in hack/lab/profiles: $(shell ls hack/lab/profiles | sed 's/\.sh//' | tr '\n' ' ')

PROFILE ?= calico

lab:
	hack/lab/lab.sh up $(PROFILE)

lab-down:
	hack/lab/lab.sh down $(PROFILE)

# Everything, one command: every profile x every scenario, then a summary.
#   make matrix                       all profiles
#   make matrix PROFILES="calico cilium"
matrix: oracle
	hack/lab/matrix.sh $(PROFILES)

# --- scenario corpus (see internal/scenario) ---

oracle-deps:
	@test -d $(NPA_DIR) || git clone -q https://github.com/kubernetes-sigs/network-policy-api.git $(NPA_DIR)
	git -C $(NPA_DIR) fetch -q origin $(NPA_SHA) && git -C $(NPA_DIR) checkout -q $(NPA_SHA)

oracle: oracle-deps
	cd hack/oracle && go build -o ../../bin/oracle .

# Measure one scenario on a running lab: make scenario NAME=demo-payments PROFILE=calico
scenario: oracle
	hack/scenarios/run.sh testdata/scenarios/$(NAME) $$(hack/lab/lab.sh kubeconfig $(PROFILE)) $(PROFILE)

corpus-summary: oracle
	bin/oracle summary testdata/scenarios

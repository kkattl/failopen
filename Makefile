CLUSTER    := failopen-demo
KUBECONFIG := $(CURDIR)/hack/demo/kubeconfig
KCTL       := kubectl --kubeconfig=$(KUBECONFIG)
CALICO_VER := v3.28.0
# policy-assistant (NetworkPolicy matcher) pinned for the oracle.
NPA_SHA    := 318a5176525c3dff6e5c406cb8f745506b73194e
NPA_DIR    := hack/oracle/.deps/network-policy-api

.PHONY: demo audit demo-down build oracle-deps oracle scenario

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

# --- scenario corpus (see internal/scenario) ---

oracle-deps:
	@test -d $(NPA_DIR) || git clone -q https://github.com/kubernetes-sigs/network-policy-api.git $(NPA_DIR)
	git -C $(NPA_DIR) fetch -q origin $(NPA_SHA) && git -C $(NPA_DIR) checkout -q $(NPA_SHA)

oracle: oracle-deps
	cd hack/oracle && go build -o ../../bin/oracle .

# Measure a scenario on the running cluster: make scenario NAME=demo-payments
scenario: oracle
	hack/scenarios/run.sh testdata/scenarios/$(NAME) $(KUBECONFIG)

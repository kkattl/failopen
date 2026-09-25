CLUSTER    := failopen-demo
KUBECONFIG := $(PWD)/hack/demo/kubeconfig
KCTL       := kubectl --kubeconfig=$(KUBECONFIG)
CALICO_VER := v3.28.0

.PHONY: demo audit demo-down build

demo:
	kind create cluster --name $(CLUSTER) \
		--config hack/demo/kind-config.yaml \
		--kubeconfig $(KUBECONFIG)
	$(KCTL) apply -f https://raw.githubusercontent.com/projectcalico/calico/$(CALICO_VER)/manifests/calico.yaml
	$(KCTL) -n kube-system rollout status ds/calico-node --timeout=180s
	$(KCTL) apply -f hack/demo/scenario.yaml
	@echo "demo cluster ready. run: make audit"

audit: build
	./bin/failopen audit --kubeconfig $(KUBECONFIG)

build:
	go build -o bin/failopen ./cmd/failopen

demo-down:
	kind delete cluster --name $(CLUSTER)

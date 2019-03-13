IMAGE := kubetoken:latest

start_container:
	docker run \
		--rm \
		-it \
		-p 48080:48080 \
                -v ${PWD}:/go/src/github.com/invia-de/kubetoken \
		--name kubetoken \
	${IMAGE}
build_container:
	docker build -t kubetoken .
run_container:
	docker run \
                --rm \
                -it \
                -v ${PWD}:/go/src/github.com/invia-de/kubetoken \
                -p 48080:48080 \
                --name kubetoken \
        ${IMAGE} \
	/bin/bash
deps:
	go get ./...
build-kubetoken:
	go build -ldflags="-X github.com/invia-de/kubetoken.Version=1.0.0" -o dist/kubetoken ./cmd/kubetoken
build-kubetokend:
	go build -ldflags="-X github.com/invia-de/kubetoken.Version=1.0.0" -o dist/kubetokend ./cmd/kubetokend

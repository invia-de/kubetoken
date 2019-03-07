IMAGE := kubetoken:latest

start_container:
	docker run \
		--rm \
		-it \
		-p 48080:48080 \
                -v ${PWD}:/go/src/github.com/atlassian/kubetoken \
		--name kubetoken \
	${IMAGE}
build_container:
	docker build -t kubetoken .
run_container:
	docker run \
                --rm \
                -it \
                -v ${PWD}:/go/src/github.com/atlassian/kubetoken \
                -p 48080:48080 \
                --name kubetoken \
        ${IMAGE} \
	/bin/bash

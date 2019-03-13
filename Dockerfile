FROM golang:latest as builder
RUN mkdir -p /go/src/github.com/invia-de/kubetoken
COPY . /go/src/github.com/invia-de/kubetoken/.
WORKDIR /go/src/github.com/invia-de/kubetoken
RUN go get ./...
ARG KUBETOKEND_HOST=https://kube-signin.example.com
RUN go build -x
RUN go build -x -ldflags="-X github.com/invia-de/kubetoken.Version=1.0.0" ./cmd/kubetokend
RUN go build -x -ldflags="-X github.com/invia-de/kubetoken.Version=1.0.0" ./cmd/kubetoken


FROM ubuntu:16.04
RUN apt-get update && apt-get install ca-certificates -y && apt-get install curl sudo -y
COPY --from=builder /go/src/github.com/invia-de/kubetoken/kubetokend /bin/kubetokend
COPY --from=builder /go/src/github.com/invia-de/kubetoken/kubetoken /bin/kubetoken
RUN mkdir -p /go/src/github.com/invia-de/kubetoken
COPY . /go/src/github.com/invia-de/kubetoken/.
WORKDIR /go/src/github.com/invia-de/kubetoken
RUN curl -LO https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl
RUN chmod +x ./kubectl
RUN sudo mv ./kubectl /usr/local/bin/kubectl
ENV PORT=8080
EXPOSE $PORT
CMD /bin/kubetokend --config=/go/src/github.com/invia-de/kubetoken/config/kubetoken.json

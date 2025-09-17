FROM golang:1.24
RUN apt-get update && apt-get install -y \
	clang \
	llvm
COPY . /go/src/github.com/cilium/ebpf
WORKDIR /go/src/github.com/cilium/ebpf/examples/
RUN cd hello_c && \
	GOPACKAGE=main go run github.com/cilium/ebpf/cmd/bpf2go -tags linux bpf hello.c -- -I../headers && \
	go build . && \
	cd ..

RUN cd hello_go && \
	go build .

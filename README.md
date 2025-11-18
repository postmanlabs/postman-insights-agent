# Welcome! 👋

Postman Insights is designed to let you optimize your API performance in real
time. Using the drop-in Postman Insights Agent, you can bring your API
endpoints into Postman and assess your API traffic. Postman Insights allows you
to create collections based on the endpoints you're interested in the most, so
you can visually inspect your API productivity and fix any errors that may
occur.

Postman is working toward the open launch of Postman Insights. Today, the alpha
release enables you to leverage the Postman Insights Agent on Amazon Elastic
Container Service (ECS) deployments. Within 15 minutes of installing the
Postman Insights Agent in staging or production, you'll start to see endpoints.
The Postman Insights Agent will keep these endpoints up to date based on new
observed traffic and its errors, latency, and volume.

We're excited for you to try out the new features and give us your feedback so
we can continue tailoring the product to your needs.

  [About this repo](#about-this-repo)
| [Running this repo](#running-this-repo)

## About this repo
This is the open-source repository for the community version of the Postman
Insights Agent, and is intended for use with Postman. This community version of
the Postman Insights Agent does not include functionality for inferring types
and data formats. This functionality is available only in the
`postman-insights-agent` binary that we distribute.

## Running this repo

### How to build
Running the following commands will generate the `postman-insights-agent`
binary:
1. Install [Go 1.18 or above](https://golang.org/doc/install).
2. Install `libpcap`
    - For Homebrew on mac: `brew install libpcap`
    - For Ubuntu/Debian: `apt-get install libpcap-dev`
3. `make`


### How to test

1. Install [gomock](https://github.com/golang/mock): `go get github.com/golang/mock/mockgen`
2. `make test`

### Experimental HTTPS capture

HTTPS payload capture via eBPF uprobes is now available behind an experimental
flag. The agent can attach uprobes to OpenSSL's `libssl` and stream decrypted
payloads directly into the existing collection pipeline. To enable it, supply
the `--enable-https-ebpf` flag along with one or more `--openssl-lib` paths
pointing to the `libssl.so` files used by your workloads:

```
postman-insights-agent apidump \
  --project <project-id> \
  --enable-https-ebpf \
  --openssl-lib /usr/lib/x86_64-linux-gnu/libssl.so.3
```

The feature requires the agent container to have permission to load eBPF
programs (typically `CAP_BPF` and `CAP_PERFMON`) and to read `/proc` entries for
the monitored processes.

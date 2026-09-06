### WHAT

TCP packets have a window field that advertises how much additional data the sender of the packet is currently willing to receive. In this project I intercept outgoing packets and override this value via eBPF to utilize the TCP stack to handle backpressure implementation for me.

### HOW

We create a traffic control filter that runs on packets leaving the loopback interface, the BPF program performs the filtering itself. The BPF program has a shared map with `server.c`. That map contains the scaling factor for the `Window` field in the TCP packet. Then we override the value in the original TCP packet to the scaled one, and just pass the packet onward. And the server implements an application-level SQM, that's highly inspired by [this paper](https://arxiv.org/pdf/1804.07617), and it has an altered version of CoDel that does not drop packets, rather, it scales down the `rwnd` factor for that socket.

the `client.c` is mostly vibe coded, but it does the job by putting enough pressure on the server to cause congestion. Also this is a PoC of this implementation working, so I did not bother with benchmarking.

### Helpful resources
- To understand rwnd and cwnd: https://www.rfc-editor.org/info/rfc5681/
- The paper that inspired me to build this SQM: https://arxiv.org/pdf/1804.07617
- Good resources about eBPF: https://docs.ebpf.io/, https://kernel-internals.org/bpf/, https://docs.kernel.org/bpf/libbpf/libbpf_overview.html#bpf-app-lifecycle-and-libbpf-apis, https://github.com/pinoOgni/ebpf-samples

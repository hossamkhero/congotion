#include "./headers/vmlinux.h"
#include "./headers/bpf_helpers.h" // it is included in common.h so now we need to include it manually
#include "./headers/bpf_tracing.h"
#include "./headers/bpf_core_read.h"
#include "./headers/bpf_endian.h"

struct evt_tcp_connect {
	__u32 saddr;
	__u16 sport;
	__u16 dport;
	__u32 daddr;
	pid_t pid;
};

// Define the Ring Buffer Map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // Size must be a power of 2 and multiple of page size (e.g., 256KB)
} rb_map SEC(".maps");

SEC("kprobe/tcp_connect")
int bpf_tcp_connect(struct pt_regs *ctx) {
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

	// Read source IP (IPv4)
	__u32 saddr = 0;
	bpf_core_read(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
	
	// Read source port (host byte order)
    __u16 sport = 0;
    bpf_core_read(&sport, sizeof(sport), &sk->__sk_common.skc_num);

    // Read destination port (network byte order, needs ntohs)
    __u16 dport = 0;
    bpf_core_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    dport = __bpf_ntohs(dport);  // convert to host byte order
	
    // Read destination address (network byte order, needs ntohs)
    __u32 daddr = 0;
    bpf_core_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);

	struct evt_tcp_connect *evt;
	evt = (struct evt_tcp_connect *)bpf_ringbuf_reserve(&rb_map, sizeof(struct evt_tcp_connect), 0);

	if(!evt)
		return 0;

	evt->saddr = saddr;
	evt->sport = sport;
	evt->dport = dport;
	evt->daddr = daddr;
	evt->pid = bpf_get_current_pid_tgid() >> 32;


	bpf_ringbuf_submit(evt, 0);


	// this prints into the kernel's buffers
	// u can view the results with
	// `sudo cat /sys/kernel/debug/tracing/trace_pipe`
    // bpf_printk("TCP connect from port %d to port %d (source IP: %x)\n", sport, dport, saddr);

    return 0;
}


SEC("fentry/cubictcp_cong_avoid")
int cubic_after(unsigned long long *ctx)
{
	struct sock *sk = (struct sock *)ctx[0];
	u32 acked = (u32)ctx[2];

	struct tcp_sock *tp = (struct tcp_sock *)sk;
	u32 cwnd = BPF_CORE_READ(tp, snd_cwnd);

	bpf_printk("cubic cwnd=%u acked=%u", cwnd, acked);
	return 0;
}


char LICENSE[] SEC("license") = "GPL";

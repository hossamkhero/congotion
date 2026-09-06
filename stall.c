#include "./headers/vmlinux.h"
#include "./headers/bpf_helpers.h" // it is included in common.h so now we need to include it manually
#include "./headers/bpf_tracing.h"
#include "./headers/bpf_core_read.h"
#include "./headers/bpf_endian.h"

/* (Simplified) user return codes for tcx prog type.
 * A valid tcx program must return one of these defined values. All other
 * return codes are reserved for future use. Must remain compatible with
 * their TC_ACT_* counter-parts. For compatibility in behavior, unknown
 * return codes are mapped to TCX_NEXT.
 */

/*
 * enum tcx_action_base {
 *    TCX_NEXT    = -1,
 *    TCX_PASS    = 0,
 *    TCX_DROP    = 2,
 *    TCX_REDIRECT    = 7,
 };
*/

// KV map of (port (int), rwnd scale factor (int))
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 100);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} clients_map SEC(".maps");

static __always_inline struct tcphdr *get_tcp(struct __sk_buff *skb) {
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return NULL;

	if (eth->h_proto != bpf_htons(0x0800))
		return NULL;

	struct iphdr *ip = (struct iphdr *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return NULL;

	if (ip->ihl < 5 || ip->protocol != IPPROTO_TCP)
		return NULL;

	__u32 ip_header_length = ip->ihl * 4;
	if ((void *)ip + ip_header_length > data_end)
		return NULL;

	struct tcphdr *tcp = (void *)ip + ip_header_length;
	if ((void *)(tcp + 1) > data_end)
		return NULL;

	return tcp;
}

SEC("tc")
int stall(struct __sk_buff *skb) {
	struct bpf_sock *sk = skb->sk;

	if (!sk)
		return TCX_PASS;

	__u32 src_port = sk->src_port;
	__u32 dst_port = bpf_ntohs(sk->dst_port);

	if(src_port == 8080) {
		__u32 *rwnd_scale_factor;

		rwnd_scale_factor = bpf_map_lookup_elem(&clients_map, &dst_port);

		if(rwnd_scale_factor) {
			if (*rwnd_scale_factor != 10000U)
				bpf_printk("[STALL_DEBUG]: dst_port=%d, has an assoicated rwnd_scale_factor of %d\n", dst_port, *rwnd_scale_factor);

			struct tcphdr *tcp = get_tcp(skb);

			if (!tcp)
				return TCX_PASS;

			void *data = (void *)(long)skb->data;

			__u16 old_window = tcp->window;

			__u32 scaled_window =
				((__u64)bpf_ntohs(old_window) * *rwnd_scale_factor) / 10000U;

			__u16 new_window = bpf_htons((__u16)scaled_window);

			void *data_end = (void *)(long)skb->data_end;

			struct iphdr *ip =
				data + sizeof(struct ethhdr);

			if ((void *)(ip + 1) > data_end)
				return TCX_PASS;

			__u32 checksum_offset = sizeof(struct ethhdr) + ((__u32)ip->ihl * 4) + __builtin_offsetof(struct tcphdr, check);

			tcp->window = new_window;

			bpf_l4_csum_replace(
				skb,
				checksum_offset,
				old_window,
				new_window,
				sizeof(__u16)
			);
		}
	}

	return TCX_PASS;
}


char LICENSE[] SEC("license") = "GPL";

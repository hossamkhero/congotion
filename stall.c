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

static __always_inline int is_pure_ack(struct __sk_buff *skb) {
	// Get pointers to the start and end of the packet data.
	void *data_end = (void*)(long)skb->data_end; 
	void *data = (void*)(long)skb->data;
	
    // Check if there's enough data for both Ethernet and IP headers.
    // In one shot.
    struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return 0;

	// Check if the protocol in the Ethernet header is IPv4.
	if (eth->h_proto != __builtin_bswap16(0x0800)) { // ETH_P_IP == 0x0800, but trying to not import <linux/if_ether.h>
		return 0; // Not an IPv4 packet
	}

    
	struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return 0; // Not enough data for both headers
    }

	// now we can jump into the ip's frame.
	// if data length is 0. and ONLY ack flag is turned on.
	// then this is a PURE ACK packet
	__u32 ip_header_length = ip->ihl * 4;

	if (ip->ihl < 5)
		return 0;

	if ((void *)ip + ip_header_length > data_end)
		return 0;

	if (ip->protocol != IPPROTO_TCP)
		return 0;

	struct tcphdr *tcp = (void *)ip + ip_header_length;

	if ((void *)(tcp + 1) > data_end)
		return 0;

	if (tcp->doff < 5)
		return 0;

	__u32 tcphdr_len = tcp->doff * 4; // data offset, stored in 32-bit words. 1 32-bit word is 4 bytes, so since we want the number in bytes, we convert it

	if (tcphdr_len < sizeof(struct tcphdr))
		return 0;
	
	__u32 ip_total_length = bpf_ntohs(ip->tot_len);
	__u32 headers_length = ip_header_length + tcphdr_len;

	if (ip_total_length < headers_length)
		return 0;

	__u32 payload_length = ip_total_length - headers_length;

	if ((__u8 *)tcp + tcphdr_len > (__u8 *)data_end)
		return 0;
	
	// if this is a syn packet
	if(tcp->syn) {
		// we should check out the WS value.
		// +---------+---------+---------+
		// | Kind=3  |Length=3 |shift.cnt|
		// +---------+---------+---------+

		// this is an optional option, so it's stored in the dynamic part of the header.
		// which is from after the fixed part of the header
		// all the way to the doff (data offset, data start offset)
		__u8 *options = (__u8 *)(tcp + 1);

		__u32 nxtoff = 0;

		__u32 options_len = tcphdr_len - sizeof(struct tcphdr);
		for (__u32 iteration = 0; iteration < 40; iteration++) {
			if (nxtoff >= options_len)
				break;

			__u32 remaining = options_len - nxtoff;

			if (remaining < 2)
				break;

			__u8 *current = options + nxtoff;
			
			if ((void *)(current + 2) > data_end)
				break;

			__u8 kind = current[0];

			// if it's 0, we reached the end of the options list. stop
			if (kind == 0) break;

			// if it's 1, it's a NOP, and just advance by 1 byte 
			if (kind == 1) {
				nxtoff += 1;
				continue;
			}

			// check length, i.e. next byte
			__u8 len = current[1];

			if(len < 2 || len > remaining) {
				break;
			}

			if(kind == 3) { // WE FOUND IT
				// read up to len - 1, that's WS
				// I mean, the length should be 3, let's just validate that, and just read the next byte, and it's
				// simplye the shift.cnt
				if (len != 3) {
					bpf_printk("[STALL DEBUG: ERROR]: length field in kind 3 is not 1, it's %d\n", len);
					break;
				}

				if ((void *)(current + 3) > data_end)
					break;
				__u8 WS = current[2];

				__be32 src_addr = ip->saddr;
				__u16 src_port = bpf_ntohs(tcp->source);

				bpf_printk("[STALL DEBUG]: src=%pI4:%u WS=%u\n", &src_addr, src_port, WS);


				break;
			}

			// advance by length - 1, cuz we have consumed 1 byte from the kind already.
			nxtoff = nxtoff + len;
		}
	}

	if(payload_length == 0 && tcp->ack && !tcp->fin && !tcp->rst && !tcp->urg && !tcp->psh && !tcp->syn && !tcp->ece && !tcp->cwr) {
		bpf_printk("rwnd=%d\n", bpf_ntohs(tcp->window));
		return 1;
	}

	return 0;
}


static __always_inline void do_stall(struct __sk_buff *skb) {
	// Get pointers to the start and end of the packet data.
	void *data_end = (void*)(long)skb->data_end; 
	void *data = (void*)(long)skb->data;
	
    // Check if there's enough data for both Ethernet and IP headers.
    // In one shot.
    struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return;

	// Check if the protocol in the Ethernet header is IPv4.
	if (eth->h_proto != __builtin_bswap16(0x0800)) { // ETH_P_IP == 0x0800, but trying to not import <linux/if_ether.h>
		return; // Not an IPv4 packet
	}

    
	struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return; // Not enough data for both headers
    }

	// now we can jump into the ip's frame.
	// if data length is 0. and ONLY ack flag is turned on.
	// then this is a PURE ACK packet
	__u32 ip_header_length = ip->ihl * 4;

	if (ip->ihl < 5)
		return;

	if ((void *)ip + ip_header_length > data_end)
		return;

	if (ip->protocol != IPPROTO_TCP)
		return;

	struct tcphdr *tcp = (void *)ip + ip_header_length;

	if ((void *)(tcp + 1) > data_end)
		return;

	if (tcp->doff < 5)
		return;

	__u32 tcphdr_len = tcp->doff * 4; // data offset, stored in 32-bit words. 1 32-bit word is 4 bytes, so since we want the number in bytes, we convert it

	if (tcphdr_len < sizeof(struct tcphdr))
		return;
	
	__u32 ip_total_length = bpf_ntohs(ip->tot_len);
	__u32 headers_length = ip_header_length + tcphdr_len;

	if (ip_total_length < headers_length)
		return;

	__u32 payload_length = ip_total_length - headers_length;

	if ((__u8 *)tcp + tcphdr_len > (__u8 *)data_end)
		return;


	if(tcp->ack) {
		bpf_printk("rwnd=%d\n", bpf_ntohs(tcp->window));
		tcp->window = bpf_htons(0);
		return;
	}
}

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

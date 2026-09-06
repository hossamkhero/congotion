#include "./headers/vmlinux.h"
#include "./headers/bpf_helpers.h" // it is included in common.h so now we need to include it manually
#include "./headers/bpf_tracing.h"
#include "./headers/bpf_core_read.h"
#include "./headers/bpf_endian.h"

extern void cubictcp_init(struct sock *sk) __ksym;
extern u32 cubictcp_recalc_ssthresh(struct sock *sk) __ksym;
extern void cubictcp_state(struct sock *sk, u8 new_state) __ksym;
extern void cubictcp_cwnd_event(struct sock *sk, enum tcp_ca_event event) __ksym;
extern void cubictcp_acked(struct sock *sk, const struct ack_sample *sample) __ksym;
extern u32 tcp_reno_undo_cwnd(struct sock *sk) __ksym;

#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))

#define BICTCP_BETA_SCALE 1024
#define BICTCP_HZ 10

static const int beta = 717;
static const int bic_scale = 41;
static int tcp_friendliness = 1;

static const u32 cube_rtt_scale = bic_scale * 10;
static const u32 beta_scale = 8 * (BICTCP_BETA_SCALE + beta) / 3 /
			      (BICTCP_BETA_SCALE - beta);
static const u64 cube_factor = (1ULL << (10 + 3 * BICTCP_HZ)) /
			       (bic_scale * 10);

/* Delegates to CUBIC's existing state callback. */
SEC("struct_ops/my_set_state")
void my_set_state(unsigned long long *ctx)
{
	struct sock *sk = (struct sock *)ctx[0];
	u8 new_state = (u8)ctx[1];

	cubictcp_state(sk, new_state);
}


/* Delegates to CUBIC's existing undo_cwnd callback. */
SEC("struct_ops/my_undo_cwnd")
u32 my_undo_cwnd(unsigned long long *ctx)
{
	struct sock *sk = (struct sock *)ctx[0];

	return tcp_reno_undo_cwnd(sk);
}


/* Delegates to CUBIC's existing cwnd_event callback. */
SEC("struct_ops/my_cwnd_event")
void my_cwnd_event(unsigned long long *ctx)
{
	struct sock *sk = (struct sock *)ctx[0];
	enum tcp_ca_event event = (enum tcp_ca_event)ctx[1];

	cubictcp_cwnd_event(sk, event);
}


/* Delegates to CUBIC's existing pkts_acked callback. */
SEC("struct_ops/my_pkts_acked")
void my_pkts_acked(unsigned long long *ctx)
{
	struct sock *sk = (struct sock *)ctx[0];
	const struct ack_sample *sample =
		(const struct ack_sample *)ctx[1];

	cubictcp_acked(sk, sample);
}

/* Delegates to CUBIC's existing init callback. */
SEC("struct_ops/my_init")
void my_init(unsigned long long *ctx)
{
	struct sock *sk = (struct sock *)ctx[0];
	cubictcp_init(sk);
}


/* Delegates to CUBIC's existing ssthresh callback. */
SEC("struct_ops/my_ssthresh")
u32 my_ssthresh(unsigned long long *ctx)
{
	struct sock *sk = (struct sock *)ctx[0];

	return cubictcp_recalc_ssthresh(sk);
}

static inline u32 tcp_snd_cwnd(const struct tcp_sock *tp)
{
	return tp->snd_cwnd;
}

static inline bool tcp_in_slow_start(const struct tcp_sock *tp)
{
	return tcp_snd_cwnd(tp) < tp->snd_ssthresh;
}

static inline bool tcp_is_cwnd_limited(const struct sock *sk)
{
	struct tcp_sock *tp = (struct tcp_sock *)sk;

	if (tp->is_cwnd_limited)
		return true;

	/* If in slow start, ensure cwnd grows to twice what was ACKed. */
	if (tcp_in_slow_start(tp))
		return tcp_snd_cwnd(tp) < 2 * tp->max_packets_out;

	return false;
}

static inline void tcp_snd_cwnd_set(struct tcp_sock *tp, u32 val)
{
	tp->snd_cwnd = val;
}

static __always_inline u32 tcp_slow_start(struct tcp_sock *tp, u32 acked)
{
	u32 cwnd = min(tcp_snd_cwnd(tp) + acked, tp->snd_ssthresh);

	acked -= cwnd - tcp_snd_cwnd(tp);
	tcp_snd_cwnd_set(tp, min(cwnd, tp->snd_cwnd_clamp));

	return acked;
}

static inline u64 div64_u64(u64 dividend, u64 divisor)
{
	return dividend / divisor;
}

#define BITS_PER_U64 64

static __always_inline int fls64(__u64 x)
{
  int num = BITS_PER_U64 - 1;

  if (x == 0)
	  return 0;

  if (!(x & (~0ULL << 32))) {
	  num -= 32;
	  x <<= 32;
  }

  if (!(x & (~0ULL << 48))) {
	  num -= 16;
	  x <<= 16;
  }

  if (!(x & (~0ULL << 56))) {
	  num -= 8;
	  x <<= 8;
  }

  if (!(x & (~0ULL << 60))) {
	  num -= 4;
	  x <<= 4;
  }

  if (!(x & (~0ULL << 62))) {
	  num -= 2;
	  x <<= 2;
  }

  if (!(x & (~0ULL << 63)))
	  num -= 1;

  return num + 1;
}

static u32 cubic_root(u64 a)
{
	u32 x, b, shift;
	/*
	 * cbrt(x) MSB values for x MSB values in [0..63].
	 * Precomputed then refined by hand - Willy Tarreau
	 *
	 * For x in [0..63],
	 *   v = cbrt(x << 18) - 1
	 *   cbrt(x) = (v[x] + 10) >> 6
	 */
	static const u8 v[] = {
		/* 0x00 */    0,   54,   54,   54,  118,  118,  118,  118,
		/* 0x08 */  123,  129,  134,  138,  143,  147,  151,  156,
		/* 0x10 */  157,  161,  164,  168,  170,  173,  176,  179,
		/* 0x18 */  181,  185,  187,  190,  192,  194,  197,  199,
		/* 0x20 */  200,  202,  204,  206,  209,  211,  213,  215,
		/* 0x28 */  217,  219,  221,  222,  224,  225,  227,  229,
		/* 0x30 */  231,  232,  234,  236,  237,  239,  240,  242,
		/* 0x38 */  244,  245,  246,  248,  250,  251,  252,  254,
	};

	/* Keep Clang from replacing this scalar bound with a source-level
	 * comparison that the BPF verifier cannot relate back to a.
	 */
	asm volatile("" : "+r"(a));

	/* State the array bound directly so the BPF verifier can prove it. */
	if (a < 64)
		return ((u32)v[(u32)a] + 35) >> 6;

	b = fls64(a);

	b = ((b * 84) >> 8) - 1;
	shift = (a >> (b * 3));
	/* Make the lookup bound explicit to the BPF verifier. */
	if (shift >= 64)
		return 0;

	x = ((u32)(((u32)v[shift] + 10) << b)) >> 6;

	/*
	 * Newton-Raphson iteration
	 *                         2
	 * x    = ( 2 * x  +  a / x  ) / 3
	 *  k+1          k         k
	 */
	x = (2 * x + (u32)div64_u64(a, (u64)x * (u64)(x - 1)));
	x = ((x * 341) >> 10);
	return x;
}

extern unsigned long CONFIG_HZ __kconfig;

#define HZ CONFIG_HZ
#define tcp_jiffies32 ((__u32)bpf_jiffies64())
#define USEC_PER_SEC 1000000UL
#define USEC_PER_JIFFY (USEC_PER_SEC / HZ)

static inline void bictcp_update(struct bictcp *ca, u32 cwnd, u32 acked)
{
	u32 delta, bic_target, max_cnt;
	u64 offs, t;

	ca->ack_cnt += acked;	/* count the number of ACKed packets */

	if (ca->last_cwnd == cwnd &&
	    (s32)(tcp_jiffies32 - ca->last_time) <= HZ / 32)
		return;

	/* The CUBIC function can update ca->cnt at most once per jiffy.
	 * On all cwnd reduction events, ca->epoch_start is set to 0,
	 * which will force a recalculation of ca->cnt.
	 */
	if (ca->epoch_start && tcp_jiffies32 == ca->last_time)
		goto tcp_friendliness;

	ca->last_cwnd = cwnd;
	ca->last_time = tcp_jiffies32;

	if (ca->epoch_start == 0) {
		ca->epoch_start = tcp_jiffies32;	/* record beginning */
		ca->ack_cnt = acked;			/* start counting */
		ca->tcp_cwnd = cwnd;			/* syn with cubic */

		if (ca->last_max_cwnd <= cwnd) {
			ca->bic_K = 0;
			ca->bic_origin_point = cwnd;
		} else {
			/* Compute new K based on
			 * (wmax-cwnd) * (srtt>>3 / HZ) / c * 2^(3*bictcp_HZ)
			 */
			ca->bic_K = cubic_root(cube_factor
					       * (ca->last_max_cwnd - cwnd));
			ca->bic_origin_point = ca->last_max_cwnd;
		}
	}

	/* cubic function - calc*/
	/* calculate c * time^3 / rtt,
	 *  while considering overflow in calculation of time^3
	 * (so time^3 is done by using 64 bit)
	 * and without the support of division of 64bit numbers
	 * (so all divisions are done by using 32 bit)
	 *  also NOTE the unit of those veriables
	 *	  time  = (t - K) / 2^bictcp_HZ
	 *	  c = bic_scale >> 10
	 * rtt  = (srtt >> 3) / HZ
	 * !!! The following code does not have overflow problems,
	 * if the cwnd < 1 million packets !!!
	 */

	/* BPF has neither usecs_to_jiffies() nor the kernel's do_div(). */
	t = (s32)(tcp_jiffies32 - ca->epoch_start) * USEC_PER_JIFFY;
	t += ca->delay_min;
	/* change the unit from usec to bictcp_HZ */
	t <<= BICTCP_HZ;
	t /= USEC_PER_SEC;

	if (t < ca->bic_K)		/* t - K */
		offs = ca->bic_K - t;
	else
		offs = t - ca->bic_K;

	/* c/rtt * (t-K)^3 */
	delta = (cube_rtt_scale * offs * offs * offs) >> (10+3*BICTCP_HZ);
	if (t < ca->bic_K)                            /* below origin*/
		bic_target = ca->bic_origin_point - delta;
	else                                          /* above origin*/
		bic_target = ca->bic_origin_point + delta;

	/* cubic function - calc bictcp_cnt*/
	if (bic_target > cwnd) {
		ca->cnt = cwnd / (bic_target - cwnd);
	} else {
		ca->cnt = 100 * cwnd;              /* very small increment*/
	}

	/*
	 * The initial growth of cubic function may be too conservative
	 * when the available bandwidth is still unknown.
	 */
	if (ca->last_max_cwnd == 0 && ca->cnt > 20)
		ca->cnt = 20;	/* increase cwnd 5% per RTT */

tcp_friendliness:
	/* TCP Friendly */
	if (tcp_friendliness) {
		u32 scale = beta_scale;
		u32 n;

		delta = (cwnd * scale) >> 3;
		/* Algebraically equivalent, without a verifier-hostile loop. */
		if (ca->ack_cnt > delta && delta) {
			n = ca->ack_cnt / delta;
			ca->ack_cnt -= n * delta;
			ca->tcp_cwnd += n;
		}

		if (ca->tcp_cwnd > cwnd) {	/* if bic is slower than tcp */
			delta = ca->tcp_cwnd - cwnd;
			max_cnt = cwnd / delta;
			if (ca->cnt > max_cnt)
				ca->cnt = max_cnt;
		}
	}

	/* The maximum rate of cwnd increase CUBIC allows is 1 packet per
	 * 2 packets ACKed, meaning cwnd grows at 1.5x per RTT.
	 */
	ca->cnt = max(ca->cnt, 2U);
}
static __always_inline void tcp_cong_avoid_ai(struct tcp_sock *tp, u32 w,
					       u32 acked)
{
	/* If credits accumulated at a higher w, apply them gently now. */
	if (tp->snd_cwnd_cnt >= w) {
		tp->snd_cwnd_cnt = 0;
		tcp_snd_cwnd_set(tp, tcp_snd_cwnd(tp) + 1);
	}

	tp->snd_cwnd_cnt += acked;
	if (tp->snd_cwnd_cnt >= w) {
		u32 delta = tp->snd_cwnd_cnt / w;

		tp->snd_cwnd_cnt -= delta * w;
		tcp_snd_cwnd_set(tp, tcp_snd_cwnd(tp) + delta);
	}
	tcp_snd_cwnd_set(tp, min(tcp_snd_cwnd(tp), tp->snd_cwnd_clamp));
}

/* Your replacement congestion-avoidance callback. */
SEC("struct_ops/my_cong_avoid")
void my_cong_avoid(unsigned long long *ctx)
{
	bpf_printk("ENTERING CONG AVOID");

	struct sock *sk = (struct sock *)ctx[0];
	u32 ack = (u32)ctx[1];
	u32 acked = (u32)ctx[2];

	struct tcp_sock *tp = (struct tcp_sock *)sk;
	struct bictcp *ca = (void *)container_of(sk, struct inet_connection_sock, icsk_inet.sk)->icsk_ca_priv;

	if (!tcp_is_cwnd_limited(sk)){
		bpf_printk("TCP CONGESTION WINDOW IS NOT LIMITED");
		return;
	}

	if (tcp_in_slow_start(tp)) {
		bpf_printk("WE ARE IN SLOW START. I REPEAT, WE ARE IN SLOW START");

		acked = tcp_slow_start(tp, acked);
		if (!acked)
			return;
	}
	bictcp_update(ca, tcp_snd_cwnd(tp), acked);
	tcp_cong_avoid_ai(tp, ca->cnt, acked);

	bpf_printk("HELLO: last=%d curr?=%d, or =%d", ca->last_cwnd, ca->tcp_cwnd, ca->cnt);
}

/* The operations table registered as a new congestion algorithm. */
SEC(".struct_ops")
struct tcp_congestion_ops my_algo = {
	.init       = (void *)my_init,
	.ssthresh   = (void *)my_ssthresh,
	.cong_avoid = (void *)my_cong_avoid,
	.set_state  = (void *)my_set_state,
	.undo_cwnd  = (void *)my_undo_cwnd,
	.cwnd_event = (void *)my_cwnd_event,
	.pkts_acked = (void *)my_pkts_acked,
	.name       = "my_algo",
};

char LICENSE[] SEC("license") = "GPL";

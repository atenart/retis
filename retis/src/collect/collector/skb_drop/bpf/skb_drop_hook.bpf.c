#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include <common.h>

struct skb_drop_event {
	s32 drop_reason;
	u64 location;
} __binding;

static __always_inline int drop_reason_arg_offset(struct retis_context *ctx) {
	int offset;

	offset = retis_arg_offset(ctx, enum skb_drop_reason);
	if (offset >= 0)
		return offset;
#if 0	// FIXME: add defs in vmlinux.h
	offset = retis_arg_offset(ctx, enum mac80211_drop_reason);
	if (offset >= 0)
		return offset;
	offset = retis_arg_offset(ctx, enum ovs_drop_reason);
	if (offset >= 0)
		return offset;
	offset = retis_arg_offset(ctx, enum qdisc_drop_reason);
	if (offset >= 0)
		return offset;
#endif

	return -1;
}

DEFINE_HOOK(
	int dr_offset = drop_reason_arg_offset(ctx);
	struct skb_drop_event *e;

	/* Check if the kernel knows about skb drop reasons, and if so check we
	 * can retrieve it. This should be the common case. In case the kernel
	 * doesn't know skb drop reasons, this hook will generate fake events
	 * and will only be attached to specific hooks.
	 */
	if (bpf_core_type_exists(enum skb_drop_reason) && dr_offset < 0)
		return 0;

	e = get_event_section(event, COLLECTOR_SKB_DROP, 1, sizeof(*e));
	if (!e)
		return 0;

	e->drop_reason = bpf_core_type_exists(enum skb_drop_reason) ?
		retis_get_arg_at(ctx, dr_offset, s32) : -1;
	e->location = is_attached_to(&ctx->ksym, "__tracepoint_kfree_skb", 22) ?
		e->location = retis_get_arg_at(ctx, 1, u64) : 0;

	return 0;
)

char __license[] SEC("license") = "GPL";

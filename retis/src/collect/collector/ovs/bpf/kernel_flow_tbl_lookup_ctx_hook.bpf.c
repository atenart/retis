#include <common.h>
#include <ovs_common.h>


/* Hook for extending the skb context in flow_tbl_lookup kretprobe */
DEFINE_CTX_HOOK(
	struct execute_actions_ctx *ectx;
	u64 sb = ctx->stack_base;

	if (retis_arg_valid(ctx, struct sk_buff *))
		return 0;

	ectx = bpf_map_lookup_elem(&inflight_exec, &sb);
	if (!ectx)
		return 0;

	retis_set_ext_arg_ptr(ctx, struct sk_buff, ectx->skb);

	return 0;
)

char __license[] SEC("license") = "GPL";

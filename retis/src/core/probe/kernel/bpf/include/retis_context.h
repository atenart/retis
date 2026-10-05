#ifndef __CORE_PROBE_KERNEL_BPF_RETIS_CONTEXT__
#define __CORE_PROBE_KERNEL_BPF_RETIS_CONTEXT__

#include <vmlinux.h>

#include <compat.h>
#include <common_defs.h>

enum kernel_probe_type {
	KERNEL_PROBE_KPROBE = 0,
	KERNEL_PROBE_KRETPROBE = 1,
	KERNEL_PROBE_TRACEPOINT = 2,
};

enum {
	REG_MAX = 11,	/* Fexit max, let's use this */

	/* Extended registers are used to store dynamically extracted
	 * arguments.
	 */
	EXT_REG,	/* Extended register */

	__EXT_REG_END,
	EXT_REG_MAX = __EXT_REG_END - 1,
};

#define REGS_SZ	EXT_REG_MAX + 1

/* Common representation of the register values provided to the probes, as this
 * is done in a per-probe type fashion.
 *
 * reg: registers values.
 * num: number of valid registers.
 */
struct retis_regs {
	u64 reg[REGS_SZ];
	u64 ret;
	u32 num; /* Number of non-extended registers in use. */
};

/* Common context information consumed by all hooks. It serves as an abstraction
 * as different probe types have different specific contexts. This information
 * will be used to provide helpers for hooks as well, e.g. to safely retrieve a
 * function parameter.
 *
 * timestamp: Timestamp of when the probe wall called, should be filled as early
 *	    as possible in the probe specific part. Then it should be left
 *	    untouched.
 * ksym:      Symbol address of the where the probe was hooked. Should also be
 *	    filled in the probe specific part. It is quite handy as it is the
 *	    only common way of understanding where a probe/hook is running.
 * regs:      Common representation of the regs of the function being probed. It
 *	    can be used to retrieve parameters, and if the probe type allows,
 *	    the returned value. Should be accessed using the get_param()
 *	    helper.
 */
struct retis_context {
	enum kernel_probe_type probe_type;
	u64 timestamp;
	u64 ksym;
	u32 args[REGS_SZ];
	struct retis_regs regs;
	/* Pointer to the original ctx. Needed for helper calls. */
	void *orig_ctx;
	u64 stack_base;
	/* Contains flags associated with the packet or the execution
	 * in its context.
	 */
	u32 flags;
};

BINDING_DEF(ARG_PTR, BIT(31))

/* Defines the bit position for each filter */
enum {
	RETIS_F_PACKET_PASS_SH = 0,
	RETIS_F_META_PASS_SH   = 1,
	RETIS_F_WINDOW_PASS_SH = 2,
};

/* Defines the bitmask for each filter */
enum {
	RETIS_F_PACKET_PASS = BIT(RETIS_F_PACKET_PASS_SH),
	RETIS_F_META_PASS   = BIT(RETIS_F_META_PASS_SH),
	RETIS_F_WINDOW_PASS = BIT(RETIS_F_WINDOW_PASS_SH),
};

#define RETIS_ALL_FILTERS	(RETIS_F_PACKET_PASS | RETIS_F_META_PASS)

/* Retrieve a probe argument offset based on its BTF id */
static __always_inline int __retis_arg_offset(struct retis_context *ctx,
					      u32 kind, u32 flags)
{
	if (kind == 0)
		return -1;

	for (int i = 0; i < MIN(ctx->regs.num, REGS_SZ); i++) {
		if ((ctx->args[i] & ~flags) == kind)
			return i;
	}

	return -1;
}
#define base(type) typeof(*__builtin_choose_expr(						\
        __builtin_classify_type((typeof(type)){0}) == __builtin_classify_type((void *)0),	\
        (typeof(type)){0}, &(typeof(type)){0}))
#define retis_arg_offset(ctx, type)								\
	(bpf_core_type_exists(base(type)) ?							\
	 __retis_arg_offset(ctx, bpf_core_type_id_kernel(base(type)),				\
		__builtin_classify_type(*(type *)0) == __builtin_classify_type((void *)0) ?	\
		ARG_PTR : 0) : -1)

/* Check if an argument is available based on its BTF id */
#define retis_arg_valid(ctx, type)	\
	(retis_arg_offset(ctx, type) >= 0)

/* Get a probe argument based on its offset in the probe arguments list. */
#define retis_get_arg_at(ctx, offset, type)	\
	(type)((offset) >= 0 && (offset) <= REG_MAX && (offset) < ctx->regs.num ? \
	ctx->regs.reg[offset] : 0)

/* Get a probe argument based on its BTF id */
#define retis_get_arg(ctx, type)	\
	retis_get_arg_at(ctx, retis_arg_offset(ctx, type), type)

/* Add an argument in the extra context space */
static __always_inline void __retis_set_ext_arg(struct retis_context *ctx,
						u32 kind, u64 arg)
{
	ctx->regs.reg[EXT_REG] = arg;
	ctx->args[EXT_REG] = kind;
}
// FIXME
#define retis_set_ext_arg(ctx, type, arg)	\
	__retis_set_ext_arg(ctx, bpf_core_type_id_kernel(type), (u64)arg)
#define retis_set_ext_arg_ptr(ctx, type, arg)	\
	__retis_set_ext_arg(ctx, bpf_core_type_id_kernel(type) | ARG_PTR, (u64)arg)

#endif /* __CORE_PROBE_KERNEL_BPF_RETIS_CONTEXT__ */

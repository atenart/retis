use anyhow::Result;

use crate::{
    bindings::{common_uapi::retis_probe_config, retis_context_uapi::*},
    core::kernel::Symbol,
};

/// Inspect a target using BTF and fill its description.
pub(super) fn inspect_symbol(symbol: &Symbol) -> Result<retis_probe_config> {
    let mut cfg = retis_probe_config::default();

    for (offset, (mut id, is_ptr)) in symbol.get_parameters_type()?.into_iter().enumerate() {
        /* FIXME */
        if offset >= 13 {
            break;
        }
        if is_ptr {
            id = id | ARG_PTR;
        }
        cfg.args[offset] = id;
    }

    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use crate::core::kernel::Symbol;

    #[test]
    fn inspect_symbol() {
        // Inspect an event.
        assert!(super::inspect_symbol(&Symbol::from_name("skb:kfree_skb").unwrap()).is_ok());

        // Inspect a function.
        assert!(super::inspect_symbol(&Symbol::from_name("kfree_skb_reason").unwrap()).is_ok());

        // Inspect a function with net device and netns arguments.
        assert!(super::inspect_symbol(&Symbol::from_name("inet_dev_addr_type").unwrap()).is_ok());
    }
}

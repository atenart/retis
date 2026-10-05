use std::ops::Deref;

use anyhow::{bail, Result};
use btf_rs::{
    utils::collection::{BtfCollection, NamedBtf},
    Backend, BtfType, Type,
};

use super::BASE_TEST_DIR;
use crate::core::kernel::Symbol;

/// Btf provides multi-module Btf lookups.
pub(crate) struct BtfInfo(BtfCollection);

impl BtfInfo {
    /// Parse kernel BTF files and create a Btf object.
    pub(super) fn new(cache: bool) -> Result<Self> {
        let dir = match cfg!(test) || cfg!(feature = "benchmark") {
            false => "/sys/kernel/btf/".to_owned(),
            true => BASE_TEST_DIR.to_owned() + "/test_data/btf/",
        };

        Ok(Self(match cache || cfg!(test) {
            true => BtfCollection::from_dir_with_backend(&dir, "vmlinux", Backend::Cache)?,
            false => {
                // Fallback to Backend::Cache for older kernels.
                BtfCollection::from_dir_with_backend(&dir, "vmlinux", Backend::Mmap).or_else(
                    |_| BtfCollection::from_dir_with_backend(&dir, "vmlinux", Backend::Cache),
                )?
            }
        }))
    }

    /// Get a function's number of arguments.
    pub(crate) fn function_nargs(&self, symbol: &Symbol) -> Result<u32> {
        // Events have a void* pointing to the data as their first argument, which
        // does not end up in their context. We have to skip it. See
        // include/trace/bpf_probe.h in the __DEFINE_EVENT definition.
        let fix = match symbol {
            Symbol::Event(_) => 1,
            _ => 0,
        };

        let (_, proto) = self.find_prototype_btf(symbol)?;

        Ok((proto.parameters.len() - fix) as u32)
    }

    /// Given a function symbol, get all its parameter (type ids, is_pointer).
    pub(crate) fn get_parameters_type(&self, symbol: &Symbol) -> Result<Vec<(u32, bool)>> {
        // Events have a void* pointing to the data as their first argument, which
        // does not end up in their context. We have to skip it. See
        // include/trace/bpf_probe.h in the __DEFINE_EVENT definition.
        let start = match symbol {
            Symbol::Event(_) => 1,
            _ => 0,
        };

        let mut params = Vec::new();

        let (btf, mut proto) = self.find_prototype_btf(symbol)?;
        for param in proto.parameters.drain(start..) {
            // Parameter have a linked type id. Same below for all unwrap calls,
            // we know for sure the definition contains a linked type.
            let mut id = param.get_type_id().unwrap();
            let mut resolved = btf.resolve_type_by_id(id)?;

            // Traverse the type definition until we get the plain type.
            let mut is_pointer = false;
            loop {
                (id, resolved) = match resolved {
                    Type::Ptr(t) => {
                        is_pointer = true;
                        (t.get_type_id().unwrap(), btf.resolve_chained_type(&t)?)
                    }
                    Type::Const(t) => (t.get_type_id().unwrap(), btf.resolve_chained_type(&t)?),
                    Type::Volatile(t) => (t.get_type_id().unwrap(), btf.resolve_chained_type(&t)?),
                    _ => break,
                };
            }

            params.push((id, is_pointer));
        }

        Ok(params)
    }

    /// Given a function symbol, get all its parameter type names (as String).
    pub(crate) fn get_parameters_name(&self, symbol: &Symbol) -> Result<Vec<String>> {
        let mut params = Vec::new();

        // Events have a void* pointing to the data as their first argument, which
        // does not end up in their context. We have to skip it. See
        // include/trace/bpf_probe.h in the __DEFINE_EVENT definition.
        let start = match symbol {
            Symbol::Event(_) => 1,
            _ => 0,
        };

        let (btf, mut proto) = self.find_prototype_btf(symbol)?;
        for param in proto.parameters.drain(start..) {
            let mut resolved = btf.resolve_chained_type(&param)?;

            // First, traverse the type definition until we find the actual type.
            // Only support valid resolve_chained_type calls and exclude function
            // pointers, static/global variables and especially typedef as we don't
            // want to traverse its full definition!
            let mut is_pointer = false;
            loop {
                resolved = match resolved {
                    Type::Ptr(t) => {
                        is_pointer = true;
                        btf.resolve_chained_type(&t)?
                    }
                    Type::Const(t) => btf.resolve_chained_type(&t)?,
                    Type::Volatile(t) => btf.resolve_chained_type(&t)?,
                    _ => break,
                };
            }

            let mut name = match resolved {
                Type::Int(t) => btf.resolve_name(&t)?,
                Type::Struct(t) => format!("struct {}", btf.resolve_name(&t)?),
                Type::Union(t) => format!("union {}", btf.resolve_name(&t)?),
                Type::Enum(t) => format!("enum {}", btf.resolve_name(&t)?),
                Type::Typedef(t) => btf.resolve_name(&t)?,
                Type::Float(t) => btf.resolve_name(&t)?,
                Type::Enum64(t) => format!("enum {}", btf.resolve_name(&t)?),
                _ => "unsupported".to_string(),
            };

            // Set the pointer information C style.
            if is_pointer {
                name.push_str(" *");
            }

            params.push(name);
        }

        Ok(params)
    }

    /// Look for a function symbol and return a Vec of matching Type objects as
    /// well as the NamedBtf object where it was found. Subsequent lookups based
    /// on this type (such as nested types by id) must be done on the returned
    /// Btf object since type ids of different modules overlap.
    pub(crate) fn resolve_types_by_symbol(
        &self,
        symbol: &Symbol,
    ) -> Result<Vec<(&NamedBtf, Type)>> {
        Ok(self.0.resolve_types_by_name(&symbol.typedef_name())?)
    }

    /// Look for symbol prototype. Return the prototype and the NamedBtf object
    /// that contains it.
    pub(crate) fn find_prototype_btf(
        &self,
        symbol: &Symbol,
    ) -> Result<(&NamedBtf, btf_rs::FuncProto)> {
        for (btf, t) in self.resolve_types_by_symbol(symbol)? {
            if let Ok(proto) = match symbol {
                Symbol::Func(_) => Self::get_function_prototype(btf, &t),
                Symbol::Event(_) => Self::get_event_prototype(btf, &t),
            } {
                return Ok((btf, proto));
            }
        }

        bail!("Failed to resolve prototype for {symbol}");
    }

    fn get_function_prototype(btf: &NamedBtf, func: &Type) -> Result<btf_rs::FuncProto> {
        // Functions are using directly the target function definition, no
        // change to make to the target format and the prototype resolution
        // is straightforward: Func -> FuncProto.
        let func = match func {
            Type::Func(func) => func,
            _ => bail!("{:?} is not a function", func),
        };

        match btf.resolve_chained_type(func)? {
            Type::FuncProto(proto) => Ok(proto),
            _ => bail!("Function {:?} does not have a prototype", func),
        }
    }

    fn get_event_prototype(btf: &NamedBtf, func: &Type) -> Result<btf_rs::FuncProto> {
        // The prototype resolution for events is:
        // Typedef -> Ptr -> FuncProto.
        let func = match func {
            Type::Typedef(func) => func,
            _ => bail!("{:?} is not a typedef", func),
        };

        let ptr = match btf.resolve_chained_type(func)? {
            Type::Ptr(ptr) => ptr,
            _ => bail!("{:?} typedef does not point to a ptr", func),
        };

        match btf.resolve_chained_type(&ptr)? {
            Type::FuncProto(proto) => Ok(proto),
            _ => bail!("Function {:?} does not have a prototype", func),
        }
    }
}

// Allow accessing the `BtfCollection` API w/o indirections.
impl Deref for BtfInfo {
    type Target = BtfCollection;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn function_nargs() {
        let btf = BtfInfo::new(false).unwrap();
        assert!(
            btf.function_nargs(&Symbol::Func("kfree_skb_reason".to_string()))
                .unwrap()
                == 2
        );

        assert!(
            btf.function_nargs(&Symbol::Func("consume_skb".to_string()))
                .unwrap()
                == 1
        );

        assert!(
            btf.function_nargs(&Symbol::Func("ovs_dp_upcall".to_string()))
                .unwrap()
                == 5
        );
    }

    #[test]
    fn parameter_offset() {
        assert!(
            Symbol::Func("kfree_skb_reason".to_string())
                .parameter_offset("struct sk_buff *")
                .unwrap()
                == Some(0)
        );

        assert!(Symbol::Func("kfree_skb_reason".to_string())
            .parameter_offset("struct sk_buff")
            .unwrap()
            .is_none());

        assert!(
            Symbol::Event("skb:kfree_skb".to_string())
                .parameter_offset("struct sk_buff *")
                .unwrap()
                == Some(0)
        );

        assert!(
            Symbol::Event("skb:kfree_skb".to_string())
                .parameter_offset("enum skb_drop_reason")
                .unwrap()
                == Some(2)
        );

        assert!(
            Symbol::Event("openvswitch:ovs_do_execute_action".to_string())
                .parameter_offset("struct sw_flow_key *")
                .unwrap()
                == Some(2)
        );

        assert!(
            Symbol::Event("openvswitch:ovs_do_execute_action".to_string())
                .parameter_offset("struct sw_flow_key")
                .unwrap()
                .is_none()
        );

        assert!(
            Symbol::Func("ovs_dp_upcall".to_string())
                .parameter_offset("struct sk_buff *")
                .unwrap()
                == Some(1)
        );

        assert!(Symbol::Func("ovs_dp_upcall".to_string())
            .parameter_offset("struct sk_buff")
            .unwrap()
            .is_none());
    }
}

//! # Bindings
//!
//! Auto-generated and extended code.
#![allow(
    dead_code,
    clippy::all,
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case
)]
pub(crate) mod common_uapi;
use common_uapi::retis_probe_config;

unsafe impl plain::Plain for retis_probe_config {}

pub(crate) mod ct_hook_uapi;
use ct_hook_uapi::ct_event;

unsafe impl plain::Plain for ct_event {}

pub(crate) mod nft_hook_uapi;

pub(crate) mod skb_drop_hook_uapi;

pub(crate) mod skb_tracking_uapi;
use skb_tracking_uapi::*;

unsafe impl plain::Plain for tracking_config {}
unsafe impl plain::Plain for tracking_info {}

pub(crate) mod tracking_hook_uapi;

pub(crate) mod if_vlan_uapi;
pub(crate) mod skb_hook_uapi;

pub(crate) mod kernel_enqueue_hook_uapi;
pub(crate) mod kernel_exec_tp_hook_uapi;
pub(crate) mod kernel_upcall_ret_hook_uapi;
pub(crate) mod kernel_upcall_tp_hook_uapi;

pub(crate) mod kernel_flow_tbl_lookup_ret_hook_uapi;
pub(crate) mod ovs_common_uapi;
pub(crate) mod ovs_operation_uapi;
pub(crate) mod user_recv_upcall_hook_uapi;

pub(crate) mod dev_common_uapi;
pub(crate) mod netns_hook_uapi;

pub(crate) mod events_uapi;
use events_uapi::retis_log_event;

unsafe impl plain::Plain for retis_log_event {}

pub(crate) mod meta_filter_uapi;
pub(crate) mod packet_filter_uapi;

pub(crate) mod retis_context_uapi;

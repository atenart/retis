use std::fmt;

use super::*;
use crate::{event_section, Formatter};

/// Device section.
#[event_section]
#[derive(Default)]
pub struct DevEvent {
    /// Device name. From `dev->name`.
    pub name: String,
    /// Ifindex. From `dev->ifindex`.
    pub ifindex: u32,
    /// Rx device ifindex. From `skb->skb_iif`.
    pub rx_ifindex: Option<u32>,
    /// Core statistic counter being increased, if any (this can only be
    /// reported from specific probes).
    pub core_stat: Option<String>,
}

impl EventFmt for DevEvent {
    fn event_fmt(&self, f: &mut Formatter, _: &DisplayFormat) -> fmt::Result {
        write!(f, "if {}", self.ifindex)?;

        if !self.name.is_empty() {
            write!(f, " ({})", self.name)?;
        }

        if let Some(rx_ifindex) = self.rx_ifindex {
            write!(f, " rxif {rx_ifindex}")?;
        }

        if let Some(core_stat) = &self.core_stat {
            write!(f, " core_stats.{core_stat}++")?;
        }

        Ok(())
    }
}

use std::fmt;

use super::*;
use crate::{event_section, Formatter};

/// Skb drop section.
#[event_section]
pub struct SkbDropEvent {
    /// Sub-system. None for core reasons.
    pub subsys: Option<String>,
    /// Reason. Only reported from specific functions.
    /// See `enum skb_drop_reason` in the kernel.
    pub drop_reason: String,
    /// Location of the drop, if any.
    pub location: Option<String>,
}

impl EventFmt for SkbDropEvent {
    fn event_fmt(&self, f: &mut Formatter, _: &DisplayFormat) -> fmt::Result {
        write!(f, "drop (reason ")?;

        if let Some(name) = &self.subsys {
            write!(f, "{name}/")?;
        }

        write!(f, "{}", self.drop_reason)?;

        if let Some(location) = &self.location {
            write!(f, " @{location}")?;
        }

        write!(f, ")")
    }
}

//! Providing forward compatibility for Python events (using the latest version
//! of Retis, Python programs written for older version should continue to
//! work).

use anyhow::{anyhow, Result};
use pyo3::types::PyAnyMethods;

use super::*;
use crate::python::PyEvent;

/// Given a Python event, make it forward compatible with a given version.
pub fn compat_fixup(
    py: pyo3::Python<'_>,
    event: &mut PyEvent,
    version: CompatVersion,
) -> Result<()> {
    // In case the version is the latest one, take the fast path.
    if version == CompatVersion::LATEST {
        return Ok(());
    }

    let event = event.0.bind(py);
    super::compatibility_fixup(&mut event.as_any(), CompatStrategy::Forward(version))
}

impl EventCompatibility for &pyo3::Bound<'_, pyo3::PyAny> {
    fn remove(&mut self, _: &str) -> Result<()> {
        // We don't support removing fields/sections in Python events.
        Ok(())
    }

    fn add(&mut self, _: &str, _: CompatValue) -> Result<()> {
        // FIXME
        // 1. Find the parent section.
        // 2. Convert the value into PyAny.
        // 3. Add the field/section and its value.
        Ok(())
    }

    fn r#move(&mut self, from: &str, to: &str) -> Result<()> {
        // Get the from field/section value.
        let mut fields = parse_target(from)?;
        let leaf = fields
            .pop()
            .ok_or_else(|| anyhow!("Invalid 'from' target ({from})"))?;
        let field = match get_field(self.clone(), fields) {
            Some(field) => field,
            None => return Ok(()),
        };
        let val = match field.getattr(leaf) {
            Ok(val) => val,
            _ => return Ok(()),
        };

        // Set the to field/section value.
        let mut fields = parse_target(to)?;
        let leaf = fields
            .pop()
            .ok_or_else(|| anyhow!("Invalid 'to' target ({to})"))?;

        let field = match get_field(self.clone(), fields) {
            Some(field) => field,
            None => return Ok(()),
        };
        field.setattr(leaf, val)?;

        println!("Moved {from} to {to}");
        println!();

        // Remove the from field/section.
        self.remove(from)
    }
}

fn get_field<'py>(
    mut attr: pyo3::Bound<'py, pyo3::PyAny>,
    target: Vec<&str>,
) -> Option<pyo3::Bound<'py, pyo3::PyAny>> {
    // Find the leaf field.
    for field in target {
        attr = match attr.getattr(field) {
            Ok(attr) if !attr.is_none() => attr,
            _ => return None,
        };
    }

    Some(attr)
}

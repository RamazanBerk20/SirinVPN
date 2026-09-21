//! Current executable selections, scoped to the authenticated Windows account.
use crate::ServiceError;
use serde::{Deserialize, Serialize};

pub(crate) const MAX_APPLICATIONS: usize = 24;
pub(crate) const BIND_CONTEXT_TAG: u32 = 0x53560101;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SelectedApplication {
    pub executable: String,
    // WFP's native path identity is captured while the local file and ancestors
    // are held open. Reapplying a guard never follows a subsequently changed link.
    pub app_id: Vec<u8>,
}
impl SelectedApplication {
    pub(crate) fn validate(&self) -> bool {
        valid_executable_path(&self.executable)
            && (8..=32768).contains(&self.app_id.len())
            && self.app_id.len().is_multiple_of(2)
            && String::from_utf16(
                &self
                    .app_id
                    .chunks_exact(2)
                    .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                    .collect::<Vec<_>>(),
            )
            .is_ok_and(|value| {
                let value = value.strip_suffix('\0').unwrap_or(&value).to_lowercase();
                value.starts_with("\\device\\harddiskvolume")
                    && value.ends_with(".exe")
                    && !value.contains('\0')
            })
    }
}

pub(crate) fn valid_executable_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    if !(7..=16000).contains(&bytes.len())
        || !bytes[0].is_ascii_alphabetic()
        || &bytes[1..3] != b":\\"
        || !value.to_ascii_lowercase().ends_with(".exe")
        || bytes[3..]
            .iter()
            .any(|byte| byte.is_ascii_control() || b"/:*?\"<>|".contains(byte))
    {
        return false;
    }
    value[3..]
        .split('\\')
        .all(|part| !part.is_empty() && part != "." && part != ".." && !part.ends_with([' ', '.']))
}

pub(crate) fn require_path(value: &str) -> Result<(), ServiceError> {
    if valid_executable_path(value) {
        Ok(())
    } else {
        Err(ServiceError::InvalidApplication)
    }
}

#[cfg(windows)]
mod native;
#[cfg(windows)]
pub(crate) use native::select;

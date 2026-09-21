use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AndroidApplicationMode {
    #[default]
    All,
    Include,
    Exclude,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AndroidApplicationRouting {
    pub mode: AndroidApplicationMode,
    pub packages: Vec<String>,
}

impl AndroidApplicationRouting {
    pub fn validated(mut self) -> Result<Self, &'static str> {
        if self.packages.len() > 32
            || (self.mode == AndroidApplicationMode::All) != self.packages.is_empty()
            || self
                .packages
                .iter()
                .any(|package| !valid_android_package(package))
        {
            return Err(
                "Choose between 1 and 32 valid application packages, or choose all applications.",
            );
        }
        self.packages.sort();
        self.packages.dedup();
        Ok(self)
    }
}

pub fn valid_android_package(value: &str) -> bool {
    value.len() <= 150
        && value.contains('.')
        && value.split('.').all(|part| {
            !part.is_empty()
                && part.as_bytes()[0].is_ascii_alphabetic()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        })
}

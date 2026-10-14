//! Text for the tray menu, tray dialogs and desktop notifications.
//!
//! English is compiled in from the frontend catalog (`locales/en/native.json`), so
//! translators edit one file. The WebView sends the active locale's messages through
//! `set_native_text`; anything it doesn't send falls back to English.
use serde_json::Value;
use std::{
    collections::HashMap,
    sync::{LazyLock, PoisonError, RwLock},
};
use tauri::AppHandle;

const SOURCE: &str = include_str!("../../src/locales/en/native.json");
const MAX_ENTRIES: usize = 512;
const MAX_CHARS: usize = 500;

static ENGLISH: LazyLock<HashMap<String, String>> = LazyLock::new(|| {
    let catalog: Value = serde_json::from_str(SOURCE).unwrap_or(Value::Null);
    let mut flat = HashMap::new();
    flatten(&catalog, "native", &mut flat);
    flat
});
static STORE: LazyLock<Store> = LazyLock::new(Store::default);

fn flatten(value: &Value, prefix: &str, out: &mut HashMap<String, String>) {
    match value {
        Value::String(text) => {
            out.insert(prefix.to_owned(), text.clone());
        }
        Value::Object(entries) => {
            for (key, value) in entries {
                flatten(value, &format!("{prefix}.{key}"), out);
            }
        }
        _ => {}
    }
}

#[derive(Default)]
struct Store(RwLock<Overrides>);

#[derive(Default)]
struct Overrides {
    revision: u64,
    texts: HashMap<String, String>,
}

impl Store {
    fn text(&self, key: &str) -> String {
        let overrides = self.0.read().unwrap_or_else(PoisonError::into_inner);
        overrides
            .texts
            .get(key)
            .or_else(|| ENGLISH.get(key))
            .cloned()
            .unwrap_or_else(|| key.to_owned())
    }

    fn revision(&self) -> u64 {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .revision
    }

    fn replace(&self, texts: HashMap<String, String>) -> Result<(), String> {
        validate(&texts)?;
        let mut overrides = self.0.write().unwrap_or_else(PoisonError::into_inner);
        overrides.texts = texts;
        overrides.revision += 1;
        Ok(())
    }
}

fn validate(texts: &HashMap<String, String>) -> Result<(), String> {
    if texts.len() > MAX_ENTRIES {
        return Err("Too many native text entries.".to_owned());
    }
    for (key, value) in texts {
        let Some(source) = ENGLISH.get(key) else {
            return Err(format!("Unknown native text key: {key}"));
        };
        if value.trim().is_empty()
            || value.chars().count() > MAX_CHARS
            || value.chars().any(|c| c.is_control() && c != '\n')
        {
            return Err(format!("Invalid native text for {key}"));
        }
        if placeholders(value) != placeholders(source) {
            return Err(format!("Native text placeholders differ for {key}"));
        }
    }
    Ok(())
}

/// Calls `visit` for each `{{name}}` placeholder with its byte range and name.
fn scan(template: &str, mut visit: impl FnMut(std::ops::Range<usize>, &str)) {
    let mut offset = 0;
    while let Some(start) = template[offset..].find("{{").map(|i| offset + i) {
        let Some(end) = template[start + 2..].find("}}").map(|i| start + 2 + i) else {
            break;
        };
        let name = template[start + 2..end].trim();
        if !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
        {
            visit(start..end + 2, name);
        }
        offset = end + 2;
    }
}

fn placeholders(template: &str) -> Vec<String> {
    let mut names = Vec::new();
    scan(template, |_, name| names.push(name.to_owned()));
    names.sort();
    names
}

fn interpolate(template: &str, params: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut copied = 0;
    scan(template, |range, name| {
        if let Some((_, value)) = params.iter().find(|(param, _)| *param == name) {
            out.push_str(&template[copied..range.start]);
            out.push_str(value);
            copied = range.end;
        }
    });
    out.push_str(&template[copied..]);
    out
}

/// The message for a `native.*` key in the active language.
pub fn text(key: &str) -> String {
    STORE.text(key)
}

/// The message for a key with its `{{name}}` placeholders filled in.
pub fn text_with(key: &str, params: &[(&str, &str)]) -> String {
    interpolate(&STORE.text(key), params)
}

/// Changes whenever the text changes, so the tray can rebuild items it doesn't compare.
pub fn revision() -> u64 {
    STORE.revision()
}

#[tauri::command]
pub fn set_native_text(app: AppHandle, texts: HashMap<String, String>) -> Result<(), String> {
    STORE.replace(texts)?;
    crate::desktop_tray::request_refresh(&app);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const SOURCES: [&str; 7] = [
        include_str!("app_preferences.rs"),
        include_str!("desktop_tray/mod.rs"),
        include_str!("desktop_tray/model.rs"),
        include_str!("desktop_tray/actions.rs"),
        include_str!("desktop_tray/navigation.rs"),
        include_str!("app_notifications.rs"),
        include_str!("connection_notifications.rs"),
    ];

    fn keys(source: &str) -> impl Iterator<Item = &str> {
        source.match_indices("\"native.").map(move |(start, _)| {
            let rest = &source[start + 1..];
            &rest[..rest.find('"').unwrap()]
        })
    }

    fn texts(entries: &[(&str, &str)]) -> HashMap<String, String> {
        entries
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn rust_and_the_catalog_use_the_same_keys() {
        let used: HashSet<_> = SOURCES.into_iter().flat_map(keys).collect();
        let missing: Vec<_> = keys(include_str!("desktop_tray/tests.rs"))
            .chain(used.iter().copied())
            .filter(|key| !ENGLISH.contains_key(*key))
            .collect();
        let unused: Vec<_> = ENGLISH
            .keys()
            .filter(|key| !used.contains(key.as_str()))
            .collect();
        assert!(missing.is_empty(), "missing from native.json: {missing:?}");
        assert!(unused.is_empty(), "unused in Rust: {unused:?}");
    }

    #[test]
    fn interpolates_named_placeholders_once() {
        assert_eq!(
            interpolate("{{ name }} · {{name}} · {{other}}", &[("name", "{{name}}")]),
            "{{name}} · {{name}} · {{other}}"
        );
        assert_eq!(
            interpolate("No {{ placeholders", &[("x", "y")]),
            "No {{ placeholders"
        );
        assert_eq!(
            text_with("native.tray.status.connectedTo", &[("name", "Home")]),
            "Connected to Home"
        );
        assert_eq!(text("native.tray.unknownKey"), "native.tray.unknownKey");
    }

    #[test]
    fn accepts_translations_and_falls_back_key_by_key() {
        let store = Store::default();
        store
            .replace(texts(&[
                ("native.tray.status.connectedTo", "Verbunden mit {{ name }}"),
                ("native.tray.confirm.quit.message", "{{status}}\nZeile zwei"),
            ]))
            .unwrap();
        assert_eq!(store.revision(), 1);
        assert_eq!(
            interpolate(
                &store.text("native.tray.status.connectedTo"),
                &[("name", "A")]
            ),
            "Verbunden mit A"
        );
        assert_eq!(store.text("native.tray.menu.open"), "Open SirinVPN");
    }

    #[test]
    fn rejects_unknown_keys_changed_placeholders_and_unsafe_values() {
        let store = Store::default();
        let long = "x".repeat(MAX_CHARS + 1);
        for entry in [
            ("native.tray.notAKey", "Text"),
            ("tray.menu.open", "Text"),
            ("native.tray.status.connectedTo", "Verbunden"),
            ("native.tray.status.connectedTo", "Verbunden mit {{server}}"),
            ("native.tray.status.connectedTo", "{{name}} {{name}}"),
            ("native.tray.menu.open", "Öffnen {{name}}"),
            ("native.tray.menu.open", "  "),
            ("native.tray.menu.open", "Öff\u{7}nen"),
            ("native.tray.menu.open", long.as_str()),
        ] {
            assert!(store.replace(texts(&[entry])).is_err(), "{entry:?}");
        }
        let many = (0..=MAX_ENTRIES)
            .map(|n| (format!("native.{n}"), String::new()))
            .collect();
        assert!(store.replace(many).is_err());
        assert_eq!(store.revision(), 0);
        assert_eq!(store.text("native.tray.menu.open"), "Open SirinVPN");
    }
}

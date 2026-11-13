// App command permissions. `build.rs` includes this file, so it stays dependency-free.
//
// The capability files are the only list: every `"allow-<command>"` in them becomes an
// app manifest command, and a registered command missing there is refused at runtime.
// To add a command, register it and add `"allow-<command-with-dashes>"` to the
// capability of each window that calls it (`capabilities/app-commands.json` for the
// desktop window, `capabilities/android.json` for Android).

/// App commands a capability file allows, in snake_case.
pub fn capability_commands(json: &str) -> Vec<String> {
    json.split('"')
        .filter_map(|text| text.strip_prefix("allow-"))
        .filter(|name| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        .map(|name| name.replace('-', "_"))
        .collect()
}

/// Command names in a source file's `generate_handler![...]` list.
pub fn handler_commands(source: &str) -> Vec<String> {
    let Some(start) = source.find("generate_handler![") else {
        return Vec::new();
    };
    let list = &source[start + "generate_handler![".len()..];
    let list = &list[..list.find("])").unwrap_or(list.len())];
    list.lines()
        .map(|line| line.split("//").next().unwrap_or_default().trim())
        .filter(|line| !line.starts_with("#["))
        .flat_map(|line| line.split(','))
        .map(|entry| entry.trim().rsplit("::").next().unwrap_or_default().to_owned())
        .filter(|name| !name.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(handlers: &str, capability: &str, file: &str) {
        let handlers = handler_commands(handlers);
        let allowed = capability_commands(capability);
        assert!(handlers.len() > 2);
        for command in &handlers {
            assert!(
                allowed.contains(command),
                "`{command}` is registered but not allowed: add \"allow-{}\" to capabilities/{file}",
                command.replace('_', "-")
            );
        }
        for command in &allowed {
            assert!(handlers.contains(command), "capabilities/{file} allows `{command}`, which isn't registered");
        }
    }

    #[test]
    fn every_registered_command_is_allowed_for_its_window() {
        check(include_str!("desktop.rs"), include_str!("../capabilities/app-commands.json"), "app-commands.json");
        check(include_str!("mobile.rs"), include_str!("../capabilities/android.json"), "android.json");
    }

    #[test]
    fn parses_handler_lists_and_permissions() {
        let source = "x generate_handler![\n a::b,\n // note, c\n #[cfg(not(windows))]\n d, e\n ]) y";
        assert_eq!(handler_commands(source), ["b", "d", "e"]);
        assert_eq!(
            capability_commands(r#"["core:default", "dialog:allow-open", "allow-pick-path", "allow-"]"#),
            ["pick_path"]
        );
    }
}

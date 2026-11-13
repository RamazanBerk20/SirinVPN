include!("src/command_acl.rs");

fn main() {
    println!("cargo:rerun-if-changed=capabilities");
    println!("cargo:rerun-if-changed=src/command_acl.rs");
    let mut commands = Vec::new();
    for entry in std::fs::read_dir("capabilities").expect("capabilities folder") {
        let path = entry.expect("capability file").path();
        if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            commands.extend(capability_commands(
                &std::fs::read_to_string(&path).expect("readable capability"),
            ));
        }
    }
    commands.sort();
    commands.dedup();
    // The unit test in `command_acl.rs` fails on these; the warning shows them sooner.
    for source in ["src/desktop.rs", "src/mobile.rs"] {
        println!("cargo:rerun-if-changed={source}");
        for command in handler_commands(&std::fs::read_to_string(source).expect("readable source"))
        {
            if !commands.contains(&command) {
                println!(
                    "cargo:warning=`{command}` is registered but no capability allows it: add \"allow-{}\" to capabilities/",
                    command.replace('_', "-")
                );
            }
        }
    }
    // With an app manifest, Tauri refuses app commands a window's capabilities don't allow.
    let commands: &'static [&'static str] = Box::leak(
        commands
            .into_iter()
            .map(|name| &*Box::leak(name.into_boxed_str()))
            .collect(),
    );
    let attributes = tauri_build::Attributes::new()
        .app_manifest(tauri_build::AppManifest::new().commands(commands));
    if let Err(error) = tauri_build::try_build(attributes) {
        panic!("{error:#}");
    }
}

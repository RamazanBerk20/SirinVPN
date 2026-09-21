#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
fn main() {
    use sirinvpn_windows_service::{install, service};
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.as_slice() == ["--version"] {
        println!("{}", env!("CARGO_PKG_VERSION"));
        return;
    }
    let result = match arguments.as_slice() {
        [argument] if argument == "--service" => service::run(),
        [argument] if argument == "--install-service" => install::install(),
        [argument] if argument == "--stop-service" => install::stop_for_update(),
        [argument] if argument == "--uninstall-service" => install::uninstall(),
        [argument, directory] if argument == "--prepare-install" => {
            install::prepare_install(std::path::Path::new(directory))
        }
        [argument, directory] if argument == "--uninstall-from" => {
            install::uninstall_from(std::path::Path::new(directory))
        }
        [argument, directory, digest]
            if argument == "--stage-update" || argument == "--stage-rollback" =>
        {
            digest
                .to_str()
                .ok_or(std::io::ErrorKind::InvalidInput.into())
                .and_then(|digest| {
                    sirinvpn_windows_service::update::stage(
                        std::path::Path::new(directory),
                        digest,
                        argument == "--stage-rollback",
                    )
                })
        }
        [argument] if argument == "--apply-update" => sirinvpn_windows_service::update::apply(),
        _ => Err(std::io::ErrorKind::InvalidInput.into()),
    };
    if result.is_err() {
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("The SirinVPN Windows networking service runs on Windows only.");
    std::process::exit(1);
}

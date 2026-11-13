use super::*;

#[derive(Parser)]
struct Command {
    #[command(flatten)]
    transport: TransportArguments,
}

fn requested(arguments: &[&str]) -> Option<sirinvpn_installer::TransportSetup> {
    Command::parse_from(std::iter::once("sirinvpn").chain(arguments.iter().copied()))
        .transport
        .requested(None)
        .unwrap()
}

#[test]
fn quic_changes_only_on_request_and_moves_a_shared_obfuscated_port() {
    assert!(requested(&[]).is_none());
    let off = requested(&["--quic", "false"]).unwrap();
    assert!(!off.quic);
    let shared = requested(&["--obfuscated-udp-port", "443", "--quic", "false"]).unwrap();
    assert_eq!(shared.obfuscated_udp_port, 443);
    let on = requested(&["--tcp-tls-port", "443", "--quic", "true"]).unwrap();
    assert!(on.quic && on.obfuscated_udp_port == sirinvpn_protocol::DEFAULT_OBFUSCATED_UDP_PORT);
    assert!(
        Command::parse_from(["sirinvpn", "--obfuscated-udp-port", "443", "--quic", "true"])
            .transport
            .requested(None)
            .is_err()
    );
}

#[test]
fn plan_applies_to_install_repair_restore_and_uninstall_without_their_confirmations() {
    let host_key = ["--host-key", "SHA256:pin"];
    let commands: [&[&str]; 4] = [
        &["add", "--name", "n", "--host", "203.0.113.4"],
        &["repair", "home"],
        &[
            "restore-vps",
            "home",
            "--input",
            "b",
            "--host",
            "203.0.113.4",
        ],
        &["uninstall", "home"],
    ];
    for command in commands {
        let arguments = ["sirinvpn", "--json", "server"]
            .into_iter()
            .chain(command.iter().copied())
            .chain(host_key)
            .chain(["--plan"]);
        let cli = Cli::try_parse_from(arguments).unwrap();
        assert!(cli.json);
        let Commands::Server { command } = cli.command else {
            panic!("wrong command")
        };
        assert!(match *command {
            ServerCommand::Add(arguments) => arguments.plan,
            ServerCommand::Repair(arguments) => arguments.plan && !arguments.confirm_repair,
            ServerCommand::RestoreVps(arguments) =>
                arguments.plan && !arguments.confirm_server_restore,
            ServerCommand::Uninstall(arguments) => arguments.plan && !arguments.confirm_uninstall,
            _ => false,
        });
    }
    assert!(
        Cli::try_parse_from([
            "sirinvpn",
            "server",
            "add",
            "--name",
            "n",
            "--host",
            "h",
            "--host-key",
            "k",
            "--plan",
            "--preflight-only"
        ])
        .is_err()
    );
}

#[test]
fn transaction_subcommands_take_only_a_login() {
    for name in ["transaction-status", "resolve"] {
        assert!(Cli::try_parse_from(["sirinvpn", "server", name, "--ssh-agent"]).is_ok());
        assert!(
            Cli::try_parse_from(["sirinvpn", "server", name, "--ssh-agent", "--ssh-key", "k"])
                .is_err()
        );
    }
}

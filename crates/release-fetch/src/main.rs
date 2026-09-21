use anyhow::Result;
use clap::Parser;
use sirinvpn_release::{ArtifactKind, ReleaseChannel};
use sirinvpn_release_fetch::{ReleaseFetchRequest, fetch_release};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "sirinvpn-release-fetch",
    version,
    about = "Fetch one root-authorized SirinVPN release artifact over bounded HTTPS"
)]
struct Cli {
    /// HTTPS directory containing the four fixed metadata files and signed artifacts.
    #[arg(long)]
    source: String,
    #[arg(long, default_value = "stable")]
    channel: ReleaseChannel,
    #[arg(long)]
    artifact_kind: ArtifactKind,
    #[arg(long)]
    artifact_target: String,
    /// New absolute directory to publish only after complete verification.
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    json: bool,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    let fetched = fetch_release(ReleaseFetchRequest {
        source: cli.source,
        expected_channel: cli.channel,
        artifact_kind: cli.artifact_kind,
        artifact_target: cli.artifact_target,
        destination: cli.output,
    })
    .await?;
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&fetched)?);
    } else {
        println!(
            "Fetched and verified SirinVPN {} release {} (sequence {}, security update: {}) with trust policy sequence {}.\nArtifact: {} ({}, {} bytes)\nBundle: {}",
            fetched.channel,
            fetched.release_version,
            fetched.release_sequence,
            fetched.security_update,
            fetched.trust_policy_sequence,
            fetched.artifact.file_name,
            fetched.artifact.kind,
            fetched.artifact.size_bytes,
            fetched.bundle_directory.display()
        );
    }
    Ok(())
}

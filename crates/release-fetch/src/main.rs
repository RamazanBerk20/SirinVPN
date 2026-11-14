use anyhow::Result;
use clap::Parser;
use sirinvpn_release::{ArtifactKind, ReleaseChannel};
use sirinvpn_release_fetch::{FetchError, FetchFailure, ReleaseFetchRequest, fetch_release};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "sirinvpn-release-fetch",
    version,
    about = "Fetch one root-authorized SirinVPN release artifact over bounded HTTPS"
)]
struct Cli {
    /// `github` for this project's GitHub Releases, or an HTTPS directory containing the four
    /// fixed metadata files, optional signed notes and artifacts.
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
    /// Also fetch the optional signed notes and print them; older callers don't pass this.
    #[arg(long)]
    release_notes: bool,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error:#}");
        // The desktop app words its own message from the exit status: 3 rate limited, 4 offline,
        // 5 no release for the channel.
        std::process::exit(
            match error.downcast_ref::<FetchError>().map(FetchError::failure) {
                Some(FetchFailure::RateLimited) => 3,
                Some(FetchFailure::Offline) => 4,
                Some(FetchFailure::NoRelease) => 5,
                _ => 1,
            },
        );
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
        release_notes: cli.release_notes,
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

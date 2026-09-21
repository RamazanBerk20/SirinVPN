use super::*;

use std::sync::atomic::{AtomicBool, Ordering};

fn keypair() -> snow::Keypair {
    let parameters: NoiseParams = NOISE_PATTERN.parse().unwrap();
    Builder::new(parameters).generate_keypair().unwrap()
}

mod replay_window_accepts_reordering_once_and_rejects_old_packets;

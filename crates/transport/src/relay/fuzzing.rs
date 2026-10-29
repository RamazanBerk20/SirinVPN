//! Obfuscated UDP relay entry point for `fuzz/`; compiled only under `--cfg fuzzing`.
use super::*;
use std::sync::OnceLock;

/// One datagram as the public relay sees it, plus what an authorized peer controls.
pub fn datagram(data: &[u8]) {
    static SESSION: OnceLock<(StatelessTransportState, StatelessTransportState)> = OnceLock::new();
    let (client, server) = SESSION.get_or_init(session);

    // Before authentication: transport framing, then the Noise responder.
    if let Some((_, sequence, ciphertext)) = parse_server_transport_packet(data) {
        let _ = decrypt_inner(server, sequence, ciphertext);
    }
    if (HANDSHAKE_MIN_LENGTH..=HANDSHAKE_MAX_LENGTH).contains(&data.len()) {
        let mut handshake = responder_handshake(&[7; 32]).unwrap();
        let _ = handshake.read_message(data, &mut [0; HANDSHAKE_MAX_LENGTH]);
    }
    HandshakeReplayCache::default().accept_client_handshake(data, [1; 32], data);

    // After authentication the peer chooses the whole plaintext of a record.
    let mut record = vec![0; data.len() + AEAD_TAG_LENGTH];
    if let Ok(length) = client.write_message(0, data, &mut record)
        && let Some(inner) = decrypt_inner(server, 0, &record[..length])
    {
        assert!(!inner.is_empty() && data[2..].starts_with(&inner));
    }

    // Sequence numbers, accepted and committed as `handle_server_transport_packet` does.
    let mut window = ReplayWindow::default();
    for sequence in data.chunks_exact(8) {
        let sequence = u64::from_be_bytes(sequence.try_into().unwrap());
        if window.accepts(sequence) {
            window.commit(sequence);
            assert!(!window.accepts(sequence));
        }
    }
}

fn session() -> (StatelessTransportState, StatelessTransportState) {
    let parameters: NoiseParams = NOISE_PATTERN.parse().unwrap();
    let server_keys = Builder::new(parameters.clone()).generate_keypair().unwrap();
    let client_keys = Builder::new(parameters).generate_keypair().unwrap();
    let mut client = initiator_handshake(
        &client_keys.private.try_into().unwrap(),
        &server_keys.public.try_into().unwrap(),
    )
    .unwrap();
    let mut server = responder_handshake(&server_keys.private.try_into().unwrap()).unwrap();
    let mut message = [0; HANDSHAKE_MAX_LENGTH];
    let length = client.write_message(&[], &mut message).unwrap();
    server.read_message(&message[..length], &mut []).unwrap();
    let length = server.write_message(&[], &mut message).unwrap();
    client.read_message(&message[..length], &mut []).unwrap();
    (
        client.into_stateless_transport_mode().unwrap(),
        server.into_stateless_transport_mode().unwrap(),
    )
}

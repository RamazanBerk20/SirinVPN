#![no_main]

use sirinvpn_release::*;

// The first byte selects a signed release document or a release public key.
// A document is accepted only in the exact canonical form its encoder writes.
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((&mode, data)) = data.split_first() else {
        return;
    };
    match mode % 6 {
        0 => {
            if let Ok(manifest) = parse_manifest(data) {
                assert_eq!(encode_manifest(&manifest).unwrap(), data);
            }
        }
        1 => {
            if let Ok(signature) = parse_signature(data) {
                assert_eq!(encode_signature(&signature).unwrap(), data);
            }
        }
        2 => {
            if let Ok(contract) = parse_compatibility_contract(data) {
                assert_eq!(encode_compatibility_contract(&contract).unwrap(), data);
            }
        }
        3 => {
            if let Ok(policy) = parse_trust_policy(data) {
                assert_eq!(encode_trust_policy(&policy).unwrap(), data);
            }
        }
        4 => {
            if let Ok(signature) = parse_trust_signature(data) {
                assert_eq!(encode_trust_signature(&signature).unwrap(), data);
            }
        }
        _ => {
            let _ = public_key_id(&String::from_utf8_lossy(data));
        }
    }
});

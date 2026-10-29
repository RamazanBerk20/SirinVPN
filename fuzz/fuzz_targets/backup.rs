#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| sirinvpn_core::fuzzing::backup(data));

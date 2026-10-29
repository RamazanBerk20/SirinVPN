#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| sirinvpn_transport::fuzzing::datagram(data));

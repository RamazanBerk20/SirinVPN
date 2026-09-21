use super::*;

#[test]
fn remote_output_is_bounded_before_reading_an_unlimited_stream() {
    let error = read_bounded_output(std::io::repeat(b'x'), 64).unwrap_err();
    assert_eq!(
        error.to_string(),
        "remote command returned an oversized response"
    );
}

#[test]
fn remote_output_accepts_empty_exact_limit_and_non_utf8_binary_data() {
    assert!(read_bounded_output(&b""[..], 64).unwrap().is_empty());
    assert_eq!(
        &*read_bounded_output(&[0xff, 0x00][..], 2).unwrap(),
        &[0xff, 0x00]
    );
    assert!(read_bounded_output(&b"abc"[..], 2).is_err());
}

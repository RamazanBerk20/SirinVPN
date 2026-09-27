use sirinvpn_platform::windows::dpapi::{self, Scope};
fn main() {
    let marker =
        std::fs::read_to_string(r"C:\ProgramData\SirinVpnAcceptance\fixture.json").unwrap();
    assert!(marker.contains("disposable_vm"));
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(args.len(), 3);
    let scope = if args[1].ends_with("-user") {
        Scope::User
    } else {
        Scope::Machine
    };
    let binding = "SirinVPN disposable native acceptance";
    if args[1] == "create-user" || args[1] == "create-machine" {
        let bytes = dpapi::protect(b"public synthetic fixture value", scope, binding).unwrap();
        std::fs::write(&args[2], bytes).unwrap();
    } else {
        assert!(args[1] == "read-user" || args[1] == "read-machine");
        let bytes = std::fs::read(&args[2]).unwrap();
        match dpapi::unprotect(&bytes, scope, binding) {
            Ok(value) => assert_eq!(value.as_slice(), b"public synthetic fixture value"),
            Err(_) => std::process::exit(42),
        }
    }
}

use super::*;
use serde_json::json;

#[test]
fn route_check_rejects_wrong_interface_and_unusable_defaults() {
    let valid = json!([
        {"dst":"default", "gateway":"192.0.2.1", "dev":"eth0"},
        {"dst":"10.77.0.0/24", "dev":"sirinvpn0"}
    ]);
    assert_eq!(route_state(&valid, "sirinvpn0", "10.77.0.0/24"), Some(true));
    for replacement in [
        json!({"dst":"default","dev":"sirinvpn0"}),
        json!({"dst":"default","dev":"eth0","flags":["linkdown"]}),
        json!({"dst":"default","dev":"eth0","type":"blackhole"}),
    ] {
        let mut invalid = valid.clone();
        invalid[0] = replacement;
        assert_eq!(
            route_state(&invalid, "sirinvpn0", "10.77.0.0/24"),
            Some(false)
        );
    }
    assert_eq!(route_state(&json!({}), "sirinvpn0", "10.77.0.0/24"), None);
}

#[test]
fn nat_requires_the_owned_hook_and_exact_tunnel_source_prefix() {
    let valid = json!({"nftables":[
        {"chain":{"family":"ip","table":"sirinvpn_nat","name":"postrouting","hook":"postrouting","type":"nat"}},
        {"rule":{"family":"ip","table":"sirinvpn_nat","chain":"postrouting","expr":[
            {"match":{"left":{"payload":{"protocol":"ip","field":"saddr"}},"op":"==","right":{"prefix":{"addr":"10.77.0.0","len":24}}}},
            {"masquerade":null}
        ]}}
    ]});
    assert_eq!(
        nat_state(&valid, "ip", "sirinvpn_nat", "10.77.0.0/24"),
        Some(true)
    );
    assert_eq!(
        nat_state(&valid, "ip", "other", "10.77.0.0/24"),
        Some(false)
    );
    assert_eq!(
        nat_state(&valid, "ip", "sirinvpn_nat", "10.78.0.0/24"),
        Some(false)
    );
    let mut wrong_hook = valid.clone();
    wrong_hook["nftables"][0]["chain"]["hook"] = json!("input");
    assert_eq!(
        nat_state(&wrong_hook, "ip", "sirinvpn_nat", "10.77.0.0/24"),
        Some(false)
    );
    let mut dnat_only = valid;
    dnat_only["nftables"][1]["rule"]["expr"][0]["match"]["left"]["payload"]["field"] =
        json!("daddr");
    assert_eq!(
        nat_state(&dnat_only, "ip", "sirinvpn_nat", "10.77.0.0/24"),
        Some(false)
    );
}

#[test]
fn sockets_require_listening_state_and_decode_private_bind_addresses() {
    if cfg!(target_endian = "little") {
        let rows = parse_listeners(
            "header\n0: 01004D0A:20FB 00000000:0000 0A\n1: 01004D0A:0035 00000000:0000 01\n",
            "0A",
        )
        .unwrap();
        assert_eq!(rows, vec![("10.77.0.1".parse().unwrap(), 8443)]);
        let rows = parse_listeners(
            "header\n0: 00000000000000000000000000000000:1F90 0:0 0A\n",
            "0A",
        )
        .unwrap();
        assert_eq!(rows, vec![("::".parse().unwrap(), 8080)]);
    }
    assert!(parse_listeners("header\nbroken", "0A").is_none());
}

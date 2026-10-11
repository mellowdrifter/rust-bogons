use bogons::*;
use std::net::IpAddr;
use std::str::FromStr;

#[test]
fn test_version() {
    assert_eq!(VERSION, "1.4.1");
}

#[test]
fn test_asn_validation() {
    let cases = [
        (0, false, "RFC 6483 / RFC 7607 (Reserved ASN 0)"),
        (1, true, ""),
        (15169, true, ""),
        (23456, false, "RFC 6793 (AS_TRANS 4-Byte Transition)"),
        (64496, false, "RFC 5398 (Documentation 16-bit)"),
        (64511, false, "RFC 5398 (Documentation 16-bit)"),
        (64512, false, "RFC 1930 / RFC 6996 (Private-Use 16-bit)"),
        (65534, false, "RFC 1930 / RFC 6996 (Private-Use 16-bit)"),
        (65535, false, "RFC 7300 (Reserved 16-bit Last ASN)"),
        (65536, false, "RFC 5398 (Documentation 32-bit)"),
        (65551, false, "RFC 5398 (Documentation 32-bit)"),
        (65552, false, "RFC 7249 / IANA (Reserved 32-bit)"),
        (131071, false, "RFC 7249 / IANA (Reserved 32-bit)"),
        (131072, true, ""),
        (4199999999, true, ""),
        (4200000000, false, "RFC 6996 (Private-Use 32-bit)"),
        (4294967294, false, "RFC 6996 (Private-Use 32-bit)"),
        (4294967295, false, "RFC 7300 (Reserved 32-bit Last ASN)"),
    ];

    for (asn, want_public, rfc_prefix) in cases {
        let is_pub = is_public_asn(asn);
        assert_eq!(is_pub, want_public, "ASN {} public check failed", asn);
        let res = check_asn(asn);
        if want_public {
            assert!(res.is_ok(), "ASN {} expected Ok, got {:?}", asn, res);
        } else {
            assert!(res.is_err(), "ASN {} expected Err", asn);
            assert!(res.unwrap_err().starts_with(rfc_prefix), "ASN {} expected reason starting with '{}', got '{}'", asn, rfc_prefix, res.unwrap_err());
        }
    }
}

#[test]
fn test_asn_parsing() {
    assert_eq!(parse_asn("15169").unwrap(), 15169);
    assert_eq!(parse_asn("AS15169").unwrap(), 15169);
    assert_eq!(parse_asn("as15169").unwrap(), 15169);
    assert_eq!(parse_asn("1.0").unwrap(), 65536);
    assert_eq!(parse_asn("1.1").unwrap(), 65537);
    assert_eq!(parse_asn("AS1.0").unwrap(), 65536);

    assert!(parse_asn("").is_err());
    assert!(parse_asn("ghost").is_err());
    assert!(parse_asn("1.2.3").is_err());
}

#[test]
fn test_ip_validation() {
    let cases = [
        // IPv4 Global Unicast
        ("1.1.1.1", true),
        ("8.8.8.8", true),
        ("192.0.1.1", true),
        // IPv4 Bogons
        ("0.0.0.1", false),
        ("127.0.0.1", false),
        ("10.1.2.3", false),
        ("172.16.1.1", false),
        ("172.31.255.255", false),
        ("192.168.1.1", false),
        ("100.64.0.1", false),
        ("169.254.1.1", false),
        ("192.0.0.1", false),
        ("192.0.2.1", false),
        ("198.51.100.1", false),
        ("203.0.113.1", false),
        ("198.18.0.1", false),
        ("198.19.255.255", false),
        ("224.0.0.1", false),
        ("240.0.0.1", false),
        ("255.255.255.255", false),
        ("192.88.99.1", false),
        ("192.31.196.1", false),
        ("192.52.193.1", false),
        ("192.0.0.170", false),
        ("192.0.0.9", false),
        // IPv6 Global Unicast
        ("2600::", true),
        ("2001:4860:4860::8888", true),
        ("3fff::1", true),
        // IPv6 Bogons
        ("::1", false),
        ("::", false),
        ("fe80::1", false),
        ("fc00::1", false),
        ("fd00::1", false),
        ("2001::1", false),
        ("2001:1:2::3", false),
        ("2001:10::1", false),
        ("2001:2::1", false),
        ("2001:db8::1", false),
        ("2002::1", false),
        ("100::1", false),
        ("64:ff9b::1", false),
        ("64:ff9b:1::1", false),
        ("3ffe::1", false),
        ("ff02::1", false),
        ("2620:4f:8000::1", false),
        ("2001:30::1", false),
        ("2001:3::1", false),
        ("4000::1", false),
        // Mapped IPv6
        ("::ffff:1.2.3.4", true),
        ("::ffff:10.0.0.1", false),
    ];

    for (ip_str, want_public) in cases {
        let is_pub = is_public_ip_str(ip_str);
        assert_eq!(is_pub, want_public, "IP {} public check failed", ip_str);

        let parsed = IpAddr::from_str(ip_str).unwrap();
        assert_eq!(is_public_ip(parsed), want_public, "Parsed IP {} check failed", ip_str);
    }

    // Malformed IP strings
    assert!(!is_public_ip_str(""));
    assert!(!is_public_ip_str("ghost"));
    assert!(!is_public_ip_str("1.1.1.1.1"));
    assert!(!is_public_ip_str(":::"));
    assert!(!is_public_ip_str("2001:db8::z"));
}

#[test]
fn test_bgp_prefix_validation() {
    // Valid IPv4 prefixes
    assert!(valid_public_prefix_str("8.8.8.0/24"));
    assert!(valid_public_prefix_str("1.1.1.0/24"));
    assert!(valid_public_prefix_str("12.0.0.0/8"));

    // Invalid IPv4 prefix lengths
    assert!(!valid_public_prefix_str("8.8.8.8/32")); // too long for BGP
    assert!(!valid_public_prefix_str("8.0.0.0/7"));  // too short for BGP
    assert!(!valid_public_prefix_str("10.0.0.0/8")); // bogon / private

    // Host bits set
    assert!(!valid_public_prefix_str("8.8.8.1/24"));

    // Valid IPv6 prefixes
    assert!(valid_public_prefix_str("2600::/16"));
    assert!(valid_public_prefix_str("2001:4860::/32"));
    assert!(valid_public_prefix_str("2a0d:1a40::/32"));
    assert!(valid_public_prefix_str("2001:4860:4860::/48"));

    // Invalid IPv6 prefix lengths
    assert!(!valid_public_prefix_str("2600::/15")); // too short for BGP
    assert!(!valid_public_prefix_str("2600::/64")); // too long for BGP
    assert!(!valid_public_prefix_str("2001:db8::/32")); // bogon / documentation

    // Host bits set in IPv6
    assert!(!valid_public_prefix_str("2001:4860::1/32"));
}

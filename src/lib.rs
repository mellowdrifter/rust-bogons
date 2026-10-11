#![cfg_attr(not(feature = "std"), no_std)]

//! # bogons
//!
//! High-performance, zero-allocation IP and ASN bogon validation library
//! with RFC descriptions and BGP announcement validity checking.
//!
//! Features:
//! - Complete parity with RFC definitions across IPv4, IPv6, and Autonomous System Numbers.
//! - Fast integer/bitmask matching with zero heap allocation (`no_std` compatible).
//! - Subnet and BGP announcement validation (/8–/24 for IPv4, /16–/48 for IPv6).
//! - Support for `asplain`, `AS`-prefixed, and `asdot` (`1.0`) ASN notation.

#[cfg(feature = "std")]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[cfg(not(feature = "std"))]
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use core::fmt;
use core::str::FromStr;

/// Semantic version of the bogons specification and library.
pub const VERSION: &str = "1.4.1";

// ---------------------------------------------------------------------------
// Internal Rules Definition
// ---------------------------------------------------------------------------

struct V4Rule {
    net: u32,
    mask: u32,
    reason: &'static str,
}

struct V6Rule {
    net: u128,
    mask: u128,
    reason: &'static str,
}

struct AsRule {
    start: u32,
    end: u32,
    reason: &'static str,
}

const fn v4_mask(bits: u8) -> u32 {
    if bits == 0 {
        0
    } else {
        !((1u64 << (32 - bits)) - 1) as u32
    }
}

const fn v6_mask(bits: u8) -> u128 {
    if bits == 0 {
        0
    } else if bits == 128 {
        u128::MAX
    } else {
        !((1u128 << (128 - bits)) - 1)
    }
}

const V4_RULES: [V4Rule; 23] = [
    V4Rule { net: 0x00000000, mask: v4_mask(8), reason: "RFC 1122 (This Host on This Network)" },
    V4Rule { net: 0x0a000000, mask: v4_mask(8), reason: "RFC 1918 (Private-Use)" },
    V4Rule { net: 0x64400000, mask: v4_mask(10), reason: "RFC 6598 (Shared Address Space / CGNAT)" },
    V4Rule { net: 0x7f000000, mask: v4_mask(8), reason: "RFC 1122 (Loopback)" },
    V4Rule { net: 0xa9fe0000, mask: v4_mask(16), reason: "RFC 3927 (Link-Local)" },
    V4Rule { net: 0xac100000, mask: v4_mask(12), reason: "RFC 1918 (Private-Use)" },
    V4Rule { net: 0xc00000aa, mask: v4_mask(31), reason: "RFC 8880 (NAT64/DNS64 Discovery)" },
    V4Rule { net: 0xc000000a, mask: v4_mask(32), reason: "RFC 8155 (TURN Anycast)" },
    V4Rule { net: 0xc0000009, mask: v4_mask(32), reason: "RFC 7725 (PCP Anycast)" },
    V4Rule { net: 0xc0000008, mask: v4_mask(32), reason: "RFC 7600 (IPv4 Dummy Address)" },
    V4Rule { net: 0xc0000000, mask: v4_mask(29), reason: "RFC 6333 / RFC 7335 (DS-Lite / Dual-Stack Continuity)" },
    V4Rule { net: 0xc0000000, mask: v4_mask(24), reason: "RFC 6890 (IETF Protocol Assignments)" },
    V4Rule { net: 0xc0000200, mask: v4_mask(24), reason: "RFC 5737 (Documentation TEST-NET-1)" },
    V4Rule { net: 0xc01fc400, mask: v4_mask(24), reason: "RFC 7535 (AS112-v4)" },
    V4Rule { net: 0xc034c100, mask: v4_mask(24), reason: "RFC 7450 (Automatic Multicast Tunneling - AMT)" },
    V4Rule { net: 0xc0586300, mask: v4_mask(24), reason: "RFC 7526 (6to4 Relay Anycast - Deprecated)" },
    V4Rule { net: 0xc0a80000, mask: v4_mask(16), reason: "RFC 1918 (Private-Use)" },
    V4Rule { net: 0xc6120000, mask: v4_mask(15), reason: "RFC 2544 (Benchmarking)" },
    V4Rule { net: 0xc6336400, mask: v4_mask(24), reason: "RFC 5737 (Documentation TEST-NET-2)" },
    V4Rule { net: 0xcb007100, mask: v4_mask(24), reason: "RFC 5737 (Documentation TEST-NET-3)" },
    V4Rule { net: 0xe0000000, mask: v4_mask(4), reason: "RFC 1112 (Multicast)" },
    V4Rule { net: 0xffffffff, mask: v4_mask(32), reason: "RFC 919 / RFC 8190 (Limited Broadcast)" },
    V4Rule { net: 0xf0000000, mask: v4_mask(4), reason: "RFC 1112 (Reserved / Former Class E)" },
];

const V6_RULES: [V6Rule; 17] = [
    // 2001:db8::/32
    V6Rule { net: 0x20010db8_00000000_00000000_00000000, mask: v6_mask(32), reason: "RFC 3849 (Documentation)" },
    // 2001::/32
    V6Rule { net: 0x20010000_00000000_00000000_00000000, mask: v6_mask(32), reason: "RFC 4380 (Teredo)" },
    // 2001:1::1/128
    V6Rule { net: 0x20010001_00000000_00000000_00000001, mask: v6_mask(128), reason: "RFC 7723 (PCP Anycast)" },
    // 2001:1::2/128
    V6Rule { net: 0x20010001_00000000_00000000_00000002, mask: v6_mask(128), reason: "RFC 8155 (TURN Anycast)" },
    // 2001:2::/48
    V6Rule { net: 0x20010002_00000000_00000000_00000000, mask: v6_mask(48), reason: "RFC 5180 / RFC 9006 (Benchmarking)" },
    // 2001:3::/32
    V6Rule { net: 0x20010003_00000000_00000000_00000000, mask: v6_mask(32), reason: "RFC 7450 (Automatic Multicast Tunneling - AMT)" },
    // 2001:4:112::/48
    V6Rule { net: 0x20010004_01120000_00000000_00000000, mask: v6_mask(48), reason: "RFC 7535 (AS112-v6)" },
    // 2001:10::/28
    V6Rule { net: 0x20010010_00000000_00000000_00000000, mask: v6_mask(28), reason: "RFC 4843 (Deprecated ORCHID)" },
    // 2001:20::/28
    V6Rule { net: 0x20010020_00000000_00000000_00000000, mask: v6_mask(28), reason: "RFC 7343 (ORCHIDv2)" },
    // 2001:30::/28
    V6Rule { net: 0x20010030_00000000_00000000_00000000, mask: v6_mask(28), reason: "RFC 9385 (Drone Remote ID)" },
    // 2001::/23
    V6Rule { net: 0x20010000_00000000_00000000_00000000, mask: v6_mask(23), reason: "RFC 2928 (IETF Protocol Assignments)" },
    // 2002::/16
    V6Rule { net: 0x20020000_00000000_00000000_00000000, mask: v6_mask(16), reason: "RFC 3056 / RFC 7526 (6to4 - Deprecated)" },
    // 2620:4f:8000::/48
    V6Rule { net: 0x2620004f_80000000_00000000_00000000, mask: v6_mask(48), reason: "RFC 7534 (Direct Delegation AS112)" },
    // 64:ff9b:1::/48
    V6Rule { net: 0x0064ff9b_00010000_00000000_00000000, mask: v6_mask(48), reason: "RFC 8215 (Local-Use IPv4/IPv6 Translation)" },
    // 64:ff9b::/96
    V6Rule { net: 0x0064ff9b_00000000_00000000_00000000, mask: v6_mask(96), reason: "RFC 6052 (IPv4/IPv6 Translation)" },
    // 100::/64
    V6Rule { net: 0x01000000_00000000_00000000_00000000, mask: v6_mask(64), reason: "RFC 6666 (Discard-Only)" },
    // 3ffe::/16
    V6Rule { net: 0x3ffe0000_00000000_00000000_00000000, mask: v6_mask(16), reason: "RFC 3701 (6bone - Deprecated / Returned)" },
];

const AS_RULES: [AsRule; 9] = [
    AsRule { start: 0, end: 0, reason: "RFC 6483 / RFC 7607 (Reserved ASN 0)" },
    AsRule { start: 23456, end: 23456, reason: "RFC 6793 (AS_TRANS 4-Byte Transition)" },
    AsRule { start: 64496, end: 64511, reason: "RFC 5398 (Documentation 16-bit)" },
    AsRule { start: 64512, end: 65534, reason: "RFC 1930 / RFC 6996 (Private-Use 16-bit)" },
    AsRule { start: 65535, end: 65535, reason: "RFC 7300 (Reserved 16-bit Last ASN)" },
    AsRule { start: 65536, end: 65551, reason: "RFC 5398 (Documentation 32-bit)" },
    AsRule { start: 65552, end: 131071, reason: "RFC 7249 / IANA (Reserved 32-bit)" },
    AsRule { start: 4200000000, end: 4294967294, reason: "RFC 6996 (Private-Use 32-bit)" },
    AsRule { start: 4294967295, end: 4294967295, reason: "RFC 7300 (Reserved 32-bit Last ASN)" },
];

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsnParseError {
    EmptyString,
    InvalidSyntax,
    OutOfRange,
}

impl fmt::Display for AsnParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyString => write!(f, "empty ASN string"),
            Self::InvalidSyntax => write!(f, "invalid ASN syntax"),
            Self::OutOfRange => write!(f, "ASN out of 32-bit range"),
        }
    }
}

// ---------------------------------------------------------------------------
// ASN Validation
// ---------------------------------------------------------------------------

/// Parse an ASN from a string. Supports plain decimal ("15169"),
/// "AS"/"as" prefix ("AS15169"), and asdot ("1.0") notation.
pub fn parse_asn(s: &str) -> Result<u32, AsnParseError> {
    let s = s.trim();
    let s = if s.starts_with("AS") || s.starts_with("as") || s.starts_with("As") || s.starts_with("aS") {
        &s[2..]
    } else {
        s
    };

    if s.is_empty() {
        return Err(AsnParseError::EmptyString);
    }

    if let Some(dot_idx) = s.find('.') {
        let (high_str, low_str) = s.split_at(dot_idx);
        let low_str = &low_str[1..];
        let high: u16 = high_str.parse().map_err(|_| AsnParseError::InvalidSyntax)?;
        let low: u16 = low_str.parse().map_err(|_| AsnParseError::InvalidSyntax)?;
        Ok(((high as u32) << 16) | (low as u32))
    } else {
        s.parse::<u32>().map_err(|_| AsnParseError::InvalidSyntax)
    }
}

/// Check whether an ASN is publicly routable.
/// Returns `Ok(())` if valid and public, or `Err(reason)` if reserved / bogon.
pub fn check_asn(asn: u32) -> Result<(), &'static str> {
    for rule in &AS_RULES {
        if asn >= rule.start && asn <= rule.end {
            return Err(rule.reason);
        }
    }
    Ok(())
}

/// Check whether an ASN is valid and publicly routable.
#[inline]
pub fn is_public_asn(asn: u32) -> bool {
    check_asn(asn).is_ok()
}

/// Check whether an ASN string (e.g. "15169", "AS15169", "1.0") is publicly routable.
pub fn check_asn_str(s: &str) -> Result<(), &'static str> {
    let asn = parse_asn(s).map_err(|_| "Invalid ASN syntax")?;
    check_asn(asn)
}

/// Reports whether the ASN string is a valid, publicly routable ASN.
#[inline]
pub fn is_public_asn_str(s: &str) -> bool {
    check_asn_str(s).is_ok()
}

// ---------------------------------------------------------------------------
// IP Validation
// ---------------------------------------------------------------------------

/// Check whether an IPv4 address is publicly routable.
pub fn check_ipv4(addr: Ipv4Addr) -> Result<(), &'static str> {
    let num = u32::from(addr);

    for rule in &V4_RULES {
        if (num & rule.mask) == rule.net {
            return Err(rule.reason);
        }
    }

    if addr.is_loopback() {
        return Err("RFC 1122 (Loopback)");
    }
    if addr.is_link_local() {
        return Err("RFC 3927 (Link-Local)");
    }
    if addr.is_multicast() {
        return Err("RFC 1112 (Multicast)");
    }
    if addr.is_broadcast() {
        return Err("RFC 919 / RFC 8190 (Limited Broadcast)");
    }

    Ok(())
}

/// Reports whether an IPv4 address is publicly routable.
#[inline]
pub fn is_public_ipv4(addr: Ipv4Addr) -> bool {
    check_ipv4(addr).is_ok()
}

/// Check whether an IPv6 address is publicly routable.
/// Handles IPv4-mapped addresses (`::ffff:x.x.x.x`) by unmapping to IPv4.
pub fn check_ipv6(addr: Ipv6Addr) -> Result<(), &'static str> {
    let octets = addr.octets();

    // Check for IPv4-mapped IPv6 (::ffff:0:0/96)
    if octets[0..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] {
        let v4 = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
        return check_ipv4(v4);
    }

    let num = u128::from(addr);

    for rule in &V6_RULES {
        if (num & rule.mask) == rule.net {
            return Err(rule.reason);
        }
    }

    if addr.is_loopback() {
        return Err("RFC 4291 (Loopback)");
    }
    if addr.is_unspecified() {
        return Err("RFC 4291 (Unspecified)");
    }
    // Link-local unicast fe80::/10
    if (octets[0] == 0xfe) && ((octets[1] & 0xc0) == 0x80) {
        return Err("RFC 4291 (Link-Local)");
    }
    // Unique local address fc00::/7
    if (octets[0] & 0xfe) == 0xfc {
        return Err("RFC 4193 (Unique Local Address / ULA)");
    }
    if addr.is_multicast() {
        return Err("RFC 4291 (Multicast)");
    }

    // Only 2000::/3 is globally routable
    if octets[0] < 0x20 || octets[0] > 0x3f {
        return Err("RFC 4291 (IANA Unallocated / Outside 2000::/3 Global Unicast)");
    }

    Ok(())
}

/// Reports whether an IPv6 address is publicly routable.
#[inline]
pub fn is_public_ipv6(addr: Ipv6Addr) -> bool {
    check_ipv6(addr).is_ok()
}

/// Check whether an IP address (v4 or v6) is publicly routable.
pub fn check_ip(addr: IpAddr) -> Result<(), &'static str> {
    match addr {
        IpAddr::V4(v4) => check_ipv4(v4),
        IpAddr::V6(v6) => check_ipv6(v6),
    }
}

/// Reports whether an IP address is publicly routable.
#[inline]
pub fn is_public_ip(addr: IpAddr) -> bool {
    check_ip(addr).is_ok()
}

/// Check whether an IP address string is valid and publicly routable.
pub fn check_ip_str(s: &str) -> Result<(), &'static str> {
    let addr = IpAddr::from_str(s.trim()).map_err(|_| "Invalid IP address syntax")?;
    check_ip(addr)
}

/// Reports whether an IP address string parses as a publicly routable IP address.
#[inline]
pub fn is_public_ip_str(s: &str) -> bool {
    check_ip_str(s).is_ok()
}

// ---------------------------------------------------------------------------
// Prefix & BGP Announcement Validation
// ---------------------------------------------------------------------------

/// Check whether a network prefix sits within publicly routable space.
/// Checks the network address against bogon subnets without enforcing BGP length bounds.
pub fn check_prefix(addr: IpAddr, _prefix_len: u8) -> Result<(), &'static str> {
    check_ip(addr)
}

/// Reports whether a network prefix sits within publicly routable space.
#[inline]
pub fn is_public_prefix(addr: IpAddr, prefix_len: u8) -> bool {
    check_prefix(addr, prefix_len).is_ok()
}

/// Reports whether prefix is a publicly routable, correctly bounded network prefix
/// suitable for BGP announcement.
///
/// IPv4: prefix length must be between /8 and /24 (inclusive).
/// IPv6: prefix length must be between /16 and /48 (inclusive).
///
/// Prefixes with host bits set (i.e. not normalized) are rejected.
pub fn valid_public_prefix(addr: IpAddr, prefix_len: u8) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            if prefix_len < 8 || prefix_len > 24 {
                return false;
            }
            let num = u32::from(v4);
            let mask = v4_mask(prefix_len);
            if (num & mask) != num {
                // Host bits are set
                return false;
            }
            is_public_ipv4(v4)
        }
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            // If IPv4-mapped IPv6, validate as IPv4
            if octets[0..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] {
                let v4 = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
                // mapped prefix lengths are usually 96 + v4_len
                let v4_len = if prefix_len >= 96 { prefix_len - 96 } else { prefix_len };
                return valid_public_prefix(IpAddr::V4(v4), v4_len);
            }

            if prefix_len < 16 || prefix_len > 48 {
                return false;
            }
            let num = u128::from(v6);
            let mask = v6_mask(prefix_len);
            if (num & mask) != num {
                // Host bits are set
                return false;
            }
            is_public_ipv6(v6)
        }
    }
}

/// Parses a CIDR prefix string (e.g. "192.0.2.0/24") and validates it for BGP announcement.
pub fn valid_public_prefix_str(s: &str) -> bool {
    let s = s.trim();
    let (ip_str, len_str) = match s.split_once('/') {
        Some(pair) => pair,
        None => return false,
    };

    let prefix_len: u8 = match len_str.parse() {
        Ok(len) => len,
        Err(_) => return false,
    };

    let addr = match IpAddr::from_str(ip_str) {
        Ok(addr) => addr,
        Err(_) => return false,
    };

    valid_public_prefix(addr, prefix_len)
}

# bogons (Rust)

[![Crates.io](https://img.shields.io/crates/v/bogons.svg)](https://crates.io/crates/bogons)
[![Docs.rs](https://docs.rs/bogons/badge.svg)](https://docs.rs/bogons)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

High-performance, zero-allocation, `no_std`-compatible Rust library for validating IP address, subnet prefix, and ASN [bogons](https://en.wikipedia.org/wiki/Bogon_filtering) with RFC descriptions.

Part of the synchronized `bogons` suite across Go, Python, Rust, C, C++, and TypeScript.

## Features

- **Blazing Fast & Zero Allocation**: Uses fast bitmask operations on integers (`u32` for IPv4, `u128` for IPv6) and static ranges for ASNs.
- **`no_std` Capable**: Fully functional in bare-metal, embedded, and kernel/eBPF environments (enabled with `default-features = false`).
- **IP Validation & Reasons**: Validates `IpAddr`, `Ipv4Addr`, `Ipv6Addr`, or strings (`check_ip`, `is_public_ip`).
- **BGP Announcement Validation**: Enforces BGP routing limits (/8–/24 for IPv4, /16–/48 for IPv6) and rejects prefixes with host bits set (`valid_public_prefix`).
- **ASN Validation & Parsing**: Validates AS numbers with exact RFC descriptions; supports `asplain` ("15169"), `AS`-prefixed ("AS15169"), and `asdot` ("1.0") notation (`parse_asn`, `check_asn`).
- **RFC Compliant**: 100% parity with RFC 1122, RFC 1918, RFC 6598, RFC 5737, RFC 7526, RFC 7535, RFC 7450, RFC 7534, RFC 9385, RFC 8880, RFC 7725, RFC 8155, RFC 6483, RFC 7300, etc.

## Multi-Language Implementations

The `bogons` library is maintained with 100% feature parity, RFC attribution, and synchronized versioning across 6 languages:

| Language | Repository (GitHub) | Package Registry | Installation |
|---|---|---|---|
| **Go** | [mellowdrifter/bogons](https://github.com/mellowdrifter/bogons) | [pkg.go.dev](https://pkg.go.dev/github.com/mellowdrifter/bogons) | `go get github.com/mellowdrifter/bogons` |
| **Python** | [mellowdrifter/python-bogons](https://github.com/mellowdrifter/python-bogons) | [PyPI](https://pypi.org/project/bogons/) | `pip install bogons` |
| **Rust** | [mellowdrifter/rust-bogons](https://github.com/mellowdrifter/rust-bogons) | [crates.io](https://crates.io/crates/bogons) | `cargo add bogons` |
| **C** | [mellowdrifter/c-bogons](https://github.com/mellowdrifter/c-bogons) | [libbogons](https://github.com/mellowdrifter/c-bogons/releases) | Single-header / `make install` |
| **C++** | [mellowdrifter/cpp-bogons](https://github.com/mellowdrifter/cpp-bogons) | [CMake / Header-only](https://github.com/mellowdrifter/cpp-bogons/releases) | `#include <bogons/bogons.hpp>` |
| **TypeScript / JS** | [mellowdrifter/ts-bogons](https://github.com/mellowdrifter/ts-bogons) | [npm](https://www.npmjs.com/package/bogons) | `npm install bogons` |

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
bogons = "1.4.1"
```

Or for `no_std` environments:

```toml
[dependencies]
bogons = { version = "1.4.1", default-features = false }
```

## Usage

### IP Validation

```rust
use bogons::{check_ip_str, is_public_ip_str};

// String checks with RFC reason
assert_eq!(check_ip_str("1.1.1.1"), Ok(()));
assert_eq!(check_ip_str("10.0.0.1"), Err("RFC 1918 (Private-Use)"));
assert_eq!(check_ip_str("2001:db8::1"), Err("RFC 3849 (Documentation)"));

// Fast boolean checks
assert!(is_public_ip_str("8.8.8.8"));
assert!(!is_public_ip_str("192.168.1.1"));
```

### ASN Validation & Parsing

```rust
use bogons::{check_asn, is_public_asn, parse_asn};

// Standard number validation
assert!(is_public_asn(15169));
assert_eq!(check_asn(64512), Err("RFC 1930 / RFC 6996 (Private-Use 16-bit)"));

// Parse decimal, AS prefix, or asdot notation
assert_eq!(parse_asn("15169").unwrap(), 15169);
assert_eq!(parse_asn("AS15169").unwrap(), 15169);
assert_eq!(parse_asn("1.0").unwrap(), 65536);
```

### BGP Announcement Validation

```rust
use bogons::valid_public_prefix_str;

// Valid announcement
assert!(valid_public_prefix_str("8.8.8.0/24"));
assert!(valid_public_prefix_str("2600::/16"));

// Rejected: too long for BGP announcement
assert!(!valid_public_prefix_str("8.8.8.8/32"));

// Rejected: host bits set (not strict network)
assert!(!valid_public_prefix_str("8.8.8.1/24"));

// Rejected: bogon / private
assert!(!valid_public_prefix_str("10.0.0.0/8"));
```

## License

Licensed under the Apache License, Version 2.0.

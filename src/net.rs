//! Source-address filtering.
//!
//! A firewall is the proper place for this, but it needs root and it does not
//! travel with the binary — so the same rule has to be rebuilt on every host and
//! is silently absent on Windows. This is defence in depth rather than a
//! replacement: on a trusted LAN it stops a device that has no business calling
//! the proxy, and it is one line of config that moves with the config.
//!
//! Note what it cannot do. A source address on a local network is trivially
//! spoofable by anyone already on that network, and behind a reverse proxy every
//! request appears to come from the proxy. Treat it as a fence, not a lock — the
//! client API key remains the thing that actually authorises a request.

use std::net::IpAddr;

/// An allow rule: a bare address, or a CIDR block.
#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    addr: IpAddr,
    /// Prefix length; a bare address is the full width of its family.
    bits: u8,
}

/// Parse `192.168.1.239`, `192.168.1.0/24`, or the v6 equivalents.
pub fn parse_rule(s: &str) -> Option<Rule> {
    let s = s.trim();
    let (addr_part, bits) = match s.split_once('/') {
        Some((a, b)) => (a, Some(b.parse::<u8>().ok()?)),
        None => (s, None),
    };
    let addr: IpAddr = addr_part.parse().ok()?;
    let width = if addr.is_ipv4() { 32 } else { 128 };
    let bits = bits.unwrap_or(width);
    (bits <= width).then_some(Rule { addr, bits })
}

fn matches(rule: &Rule, peer: IpAddr) -> bool {
    match (rule.addr, peer) {
        (IpAddr::V4(net), IpAddr::V4(ip)) => {
            // A /0 shifts by 32, which is UB for u32; handle it as "everything".
            if rule.bits == 0 {
                return true;
            }
            let mask = u32::MAX << (32 - rule.bits);
            u32::from(net) & mask == u32::from(ip) & mask
        }
        (IpAddr::V6(net), IpAddr::V6(ip)) => {
            if rule.bits == 0 {
                return true;
            }
            let mask = u128::MAX << (128 - rule.bits);
            u128::from(net) & mask == u128::from(ip) & mask
        }
        // A v4 rule never authorises a v6 caller, or the reverse. An IPv4-mapped
        // v6 address is unwrapped first so a dual-stack listener behaves the way
        // an operator expects.
        _ => match peer {
            IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .is_some_and(|v4| matches(rule, IpAddr::V4(v4))),
            _ => false,
        },
    }
}

/// Is `peer` permitted, given the configured rules?
///
/// An empty list allows everything — the setting is opt-in, and a proxy that
/// refused all traffic the moment someone saved an empty field would be a bad
/// surprise. Loopback is always allowed regardless, so a host can always reach
/// its own health probe and an operator can never lock themselves out of the
/// machine they are sitting at.
pub fn permitted(rules: &[Rule], peer: IpAddr) -> bool {
    if rules.is_empty() || peer.is_loopback() {
        return true;
    }
    if let IpAddr::V6(v6) = peer {
        if v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()) {
            return true;
        }
    }
    rules.iter().any(|r| matches(r, peer))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn rules(list: &[&str]) -> Vec<Rule> {
        list.iter().filter_map(|s| parse_rule(s)).collect()
    }

    #[test]
    fn an_empty_list_allows_everything() {
        assert!(permitted(&[], ip("8.8.8.8")));
    }

    #[test]
    fn a_single_address_admits_only_itself() {
        let r = rules(&["192.168.1.239"]);
        assert!(permitted(&r, ip("192.168.1.239")));
        assert!(!permitted(&r, ip("192.168.1.240")));
        assert!(!permitted(&r, ip("192.168.2.239")));
    }

    #[test]
    fn a_cidr_admits_its_block_and_nothing_else() {
        let r = rules(&["192.168.1.0/24"]);
        assert!(permitted(&r, ip("192.168.1.1")));
        assert!(permitted(&r, ip("192.168.1.255")));
        assert!(!permitted(&r, ip("192.168.2.1")));
    }

    /// The tailnet is one block, so remote access survives an allowlist that was
    /// written with only the LAN in mind — as long as it is listed.
    #[test]
    fn the_tailscale_range_can_be_admitted_as_a_block() {
        let r = rules(&["100.64.0.0/10"]);
        assert!(permitted(&r, ip("100.95.255.90")));
        assert!(permitted(&r, ip("100.126.90.27")));
        assert!(!permitted(&r, ip("192.168.1.239")));
    }

    /// Otherwise a host cannot probe its own health endpoint, and whoever is
    /// sitting at the machine is locked out of it.
    #[test]
    fn loopback_is_always_allowed() {
        let r = rules(&["192.168.1.239"]);
        assert!(permitted(&r, ip("127.0.0.1")));
        assert!(permitted(&r, ip("::1")));
        assert!(permitted(&r, ip("::ffff:127.0.0.1")));
    }

    #[test]
    fn a_v4_rule_does_not_admit_a_v6_caller() {
        let r = rules(&["192.168.1.239"]);
        assert!(!permitted(&r, ip("2a0d:3341:b3ed::1")));
        // ...but a dual-stack listener reporting the mapped form still works.
        assert!(permitted(&r, ip("::ffff:192.168.1.239")));
    }

    #[test]
    fn nonsense_rules_are_dropped_rather_than_admitting_everyone() {
        assert!(parse_rule("not-an-ip").is_none());
        assert!(parse_rule("192.168.1.1/99").is_none());
        assert!(parse_rule("").is_none());
        // A list of only-bad rules parses to empty, which allows all — so the
        // caller must reject bad input rather than silently opening up.
        assert!(rules(&["nonsense"]).is_empty());
    }

    #[test]
    fn a_zero_prefix_means_everything_without_overflowing() {
        assert!(permitted(&rules(&["0.0.0.0/0"]), ip("8.8.8.8")));
        assert!(permitted(&rules(&["::/0"]), ip("2a0d::1")));
    }
}

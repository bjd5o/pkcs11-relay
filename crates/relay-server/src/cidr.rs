//! Minimal CIDR matching for the pairing allow-list.

use std::net::IpAddr;

#[derive(Debug, Clone, Copy)]
pub struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Result<Self, String> {
        let (addr, prefix) = s
            .split_once('/')
            .ok_or_else(|| format!("CIDR `{s}` needs a /prefix"))?;
        let net: IpAddr = addr.parse().map_err(|_| format!("bad address in `{s}`"))?;
        let prefix: u8 = prefix.parse().map_err(|_| format!("bad prefix in `{s}`"))?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(format!("prefix too long in `{s}`"));
        }
        Ok(Cidr { net, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        // Treat IPv4-mapped IPv6 addresses as IPv4.
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            v4 => v4,
        };
        match (self.net, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                u32::from(n) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                u128::from(n) & mask == u128::from(a) & mask
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching() {
        let c = Cidr::parse("100.64.0.0/10").unwrap();
        assert!(c.contains("100.100.1.2".parse().unwrap()));
        assert!(!c.contains("100.128.0.1".parse().unwrap()));
        assert!(c.contains("::ffff:100.64.0.1".parse().unwrap()));
        let c = Cidr::parse("fd7a:115c:a1e0::/48").unwrap();
        assert!(c.contains("fd7a:115c:a1e0:ab12::1".parse().unwrap()));
        assert!(!c.contains("fd7a:115c:a1e1::1".parse().unwrap()));
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("0.0.0.0/0")
            .unwrap()
            .contains("8.8.8.8".parse().unwrap()));
    }
}

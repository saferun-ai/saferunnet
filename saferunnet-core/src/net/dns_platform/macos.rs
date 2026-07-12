use std::io;
use std::net::SocketAddr;

use super::DnsPlatform;

/// macOS DNS configuration via `/etc/resolv.conf`.
pub struct MacosDns;

impl DnsPlatform for MacosDns {
    fn set_dns(&self, servers: &[SocketAddr], _if_name: &str) -> io::Result<()> {
        if servers.is_empty() {
            return Ok(());
        }
        let path = "/etc/resolv.conf";
        let content = std::fs::read_to_string(path).unwrap_or_default();

        let mut new_lines: Vec<String> = Vec::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("nameserver ") || trimmed.starts_with("search ") || trimmed.is_empty() {
                continue;
            }
            new_lines.push(line.to_string());
        }
        for server in servers {
            new_lines.push(format!("nameserver {}", server.ip()));
        }
        std::fs::write(path, new_lines.join("\n") + "\n")?;
        Ok(())
    }

    fn remove_dns(&self, _if_name: &str) -> io::Result<()> {
        let path = "/etc/resolv.conf";
        let content = std::fs::read_to_string(path).unwrap_or_default();
        let new_lines: Vec<&str> = content
            .lines()
            .filter(|l| {
                let t = l.trim();
                !t.starts_with("nameserver ") && !t.starts_with("search ") && !t.is_empty()
            })
            .collect();
        std::fs::write(path, new_lines.join("\n") + "\n")?;
        Ok(())
    }

    fn add_search_domain(&self, domain: &str, _if_name: &str) -> io::Result<()> {
        let path = "/etc/resolv.conf";
        let content = std::fs::read_to_string(path).unwrap_or_default();

        let mut new_lines: Vec<String> = Vec::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("search ") || trimmed.is_empty() {
                continue;
            }
            new_lines.push(line.to_string());
        }
        new_lines.push(format!("search {}", domain));
        // Preserve nameserver lines
        for line in content.lines() {
            if line.trim().starts_with("nameserver ") {
                new_lines.push(line.to_string());
            }
        }
        std::fs::write(path, new_lines.join("\n") + "\n")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_dns() {
        let dns = MacosDns;
        let _ = dns.set_dns(&[], "utun3");
    }

    #[test]
    fn test_remove_dns() {
        let dns = MacosDns;
        let _ = dns.remove_dns("utun3");
    }

    #[test]
    fn test_add_search_domain() {
        let dns = MacosDns;
        let _ = dns.add_search_domain("saferunnet", "utun3");
    }
}

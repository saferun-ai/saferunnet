use std::io;
use std::net::SocketAddr;
use std::process::Command;

use super::DnsPlatform;

/// Linux DNS configuration via systemd-resolved `resolvectl` with resolv.conf fallback.
pub struct LinuxDns;

impl LinuxDns {
    /// Try setting DNS via resolvectl (systemd-resolved).
    fn resolvectl_set_dns(if_name: &str, servers: &[SocketAddr]) -> io::Result<bool> {
        let ips: Vec<String> = servers.iter().map(|s| s.ip().to_string()).collect();
        let mut args = vec!["dns", if_name];
        args.extend(ips.iter().map(|s| s.as_str()));
        let output = Command::new("resolvectl").args(&args).output()?;
        Ok(output.status.success())
    }

    /// Fallback: rewrite /etc/resolv.conf nameserver lines.
    fn resolv_conf_set_dns(servers: &[SocketAddr], search_domains: &[String]) -> io::Result<()> {
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
        for domain in search_domains {
            if !domain.is_empty() {
                new_lines.push(format!("search {}", domain));
            }
        }
        std::fs::write(path, new_lines.join("\n") + "\n")?;
        Ok(())
    }
}

impl DnsPlatform for LinuxDns {
    fn set_dns(&self, servers: &[SocketAddr], if_name: &str) -> io::Result<()> {
        if servers.is_empty() {
            return Ok(());
        }
        // Try resolvectl first
        if Self::resolvectl_set_dns(if_name, servers).unwrap_or(false) {
            return Ok(());
        }
        // Fallback to resolv.conf
        Self::resolv_conf_set_dns(servers, &[])
    }

    fn remove_dns(&self, if_name: &str) -> io::Result<()> {
        // Try resolvectl to clear DNS
        let output = Command::new("resolvectl")
            .args(["dns", if_name, ""])
            .output()?;
        if output.status.success() {
            return Ok(());
        }
        // Fallback: remove our nameserver lines from resolv.conf
        let path = "/etc/resolv.conf";
        let content = std::fs::read_to_string(path).unwrap_or_default();
        let new_lines: Vec<&str> = content
            .lines()
            .filter(|l| {
                let t = l.trim();
                !t.starts_with("nameserver ") && !t.is_empty()
            })
            .collect();
        std::fs::write(path, new_lines.join("\n") + "\n")?;
        Ok(())
    }

    fn add_search_domain(&self, domain: &str, if_name: &str) -> io::Result<()> {
        let output = Command::new("resolvectl")
            .args(["domain", if_name, domain])
            .output()?;
        if output.status.success() {
            return Ok(());
        }
        // Fallback
        Self::resolv_conf_set_dns(&[], &[domain.to_string()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_dns() {
        let dns = LinuxDns;
        let servers = vec!["127.0.0.1:53".parse().unwrap()];
        let _ = dns.set_dns(&servers, "tun0");
    }

    #[test]
    fn test_remove_dns() {
        let dns = LinuxDns;
        let _ = dns.remove_dns("tun0");
    }

    #[test]
    fn test_add_search_domain() {
        let dns = LinuxDns;
        let _ = dns.add_search_domain("saferunnet", "tun0");
    }
}

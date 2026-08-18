use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};
use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use x509_parser::prelude::*;

/// We're intentionally inspecting expiry, not establishing a trusted
/// connection, so every check is a rubber stamp: self-signed, expired, and
/// hostname-mismatched certificates all need to come through unmodified for
/// this tool to be useful.
#[derive(Debug)]
struct AcceptAnyCert;

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Status {
    /// Days until `not_after` (negative means already expired).
    Ok(i64),
    /// TCP connect, TLS handshake, or certificate parsing failed.
    Error(String),
}

#[derive(Debug, Clone)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct CertResult {
    pub target: Target,
    pub status: Status,
    pub not_after: Option<String>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
}

impl CertResult {
    /// A short, actionable hint on how to renew this certificate, guessed
    /// from who issued it. This is necessarily a guess — `certmonitor` only
    /// sees what the TLS handshake reveals, not how the target server
    /// actually manages its certificates — so treat it as a starting point,
    /// not a command to run blindly.
    pub fn renewal_hint(&self) -> &'static str {
        if matches!(self.status, Status::Error(_)) {
            return "fix connectivity first";
        }
        let (Some(subject), Some(issuer)) = (&self.subject, &self.issuer) else {
            return "-";
        };
        if subject == issuer {
            return "self-signed: regenerate manually";
        }
        let issuer_lower = issuer.to_lowercase();
        if issuer_lower.contains("let's encrypt") || issuer_lower.contains("lets encrypt") {
            "run certbot renew (or your ACME client) on the server"
        } else if issuer_lower.contains("zerossl") {
            "renew via your ACME client (ZeroSSL)"
        } else {
            "renew through the issuing CA"
        }
    }
}

/// Parse a `host:port` line. Bare hostnames default to port 443.
pub fn parse_target(line: &str) -> Option<Target> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    match line.rsplit_once(':') {
        Some((host, port)) => {
            let port: u16 = port.parse().ok()?;
            Some(Target {
                host: host.to_string(),
                port,
            })
        }
        None => Some(Target {
            host: line.to_string(),
            port: 443,
        }),
    }
}

fn tls_config() -> Arc<ClientConfig> {
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();
    Arc::new(config)
}

/// Connect to `target`, complete a TLS handshake, and read the leaf
/// certificate's validity window. Never panics; every failure mode (DNS,
/// connect, handshake, parsing) becomes a `Status::Error` in the result.
pub fn check_target(target: &Target, timeout: Duration, config: &Arc<ClientConfig>) -> CertResult {
    match check_target_inner(target, timeout, config) {
        Ok(result) => result,
        Err(e) => CertResult {
            target: target.clone(),
            status: Status::Error(e),
            not_after: None,
            subject: None,
            issuer: None,
        },
    }
}

fn check_target_inner(
    target: &Target,
    timeout: Duration,
    config: &Arc<ClientConfig>,
) -> Result<CertResult, String> {
    let addr = (target.host.as_str(), target.port)
        .to_socket_addrs()
        .map_err(|e| format!("DNS lookup failed: {e}"))?
        .next()
        .ok_or_else(|| "DNS lookup returned no addresses".to_string())?;

    let mut sock =
        TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("connect failed: {e}"))?;
    sock.set_read_timeout(Some(timeout)).ok();
    sock.set_write_timeout(Some(timeout)).ok();

    let server_name = ServerName::try_from(target.host.clone())
        .map_err(|e| format!("invalid hostname for SNI: {e}"))?;
    let mut conn = ClientConnection::new(Arc::clone(config), server_name)
        .map_err(|e| format!("failed to start TLS session: {e}"))?;

    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    // Force the handshake to complete now, so a handshake failure surfaces
    // here instead of silently on the first real read/write.
    tls.flush()
        .map_err(|e| format!("TLS handshake failed: {e}"))?;

    let certs = conn
        .peer_certificates()
        .ok_or_else(|| "server presented no certificate".to_string())?;
    let leaf = certs
        .first()
        .ok_or_else(|| "empty certificate chain".to_string())?;

    let (_, x509) = X509Certificate::from_der(leaf.as_ref())
        .map_err(|e| format!("failed to parse certificate: {e}"))?;

    let not_after = x509.validity().not_after;
    let now = ASN1Time::now();
    let days_left = (not_after.timestamp() - now.timestamp()) / 86_400;

    Ok(CertResult {
        target: target.clone(),
        status: Status::Ok(days_left),
        not_after: Some({
            let dt = not_after.to_datetime();
            format!("{:04}-{:02}-{:02}", dt.year(), dt.month() as u8, dt.day())
        }),
        subject: Some(x509.subject().to_string()),
        issuer: Some(x509.issuer().to_string()),
    })
}

/// Check every target concurrently (one thread per target — the list is
/// expected to be tens to low hundreds of hosts, not thousands), and return
/// results sorted soonest-to-expire first. Errored targets sort last.
pub fn check_all(targets: &[Target], timeout: Duration) -> Vec<CertResult> {
    let config = tls_config();
    let handles: Vec<_> = targets
        .iter()
        .cloned()
        .map(|target| {
            let config = Arc::clone(&config);
            std::thread::spawn(move || check_target(&target, timeout, &config))
        })
        .collect();

    let mut results: Vec<CertResult> = handles
        .into_iter()
        .map(|h| h.join().expect("scan thread panicked"))
        .collect();

    results.sort_by_key(|r| match &r.status {
        Status::Ok(days) => *days,
        Status::Error(_) => i64::MAX,
    });
    results
}

/// Start a scan on a background thread and return a handle to join for the
/// final (sorted) results, plus a live counter of targets checked so far
/// that the caller can poll from another thread without blocking.
pub fn check_all_async(
    targets: Vec<Target>,
    timeout: Duration,
) -> (
    std::thread::JoinHandle<Vec<CertResult>>,
    Arc<std::sync::atomic::AtomicU64>,
) {
    let progress = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let progress_for_scan = Arc::clone(&progress);
    let handle = std::thread::spawn(move || {
        let config = tls_config();
        let handles: Vec<_> = targets
            .into_iter()
            .map(|target| {
                let config = Arc::clone(&config);
                let progress = Arc::clone(&progress_for_scan);
                std::thread::spawn(move || {
                    let result = check_target(&target, timeout, &config);
                    progress.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    result
                })
            })
            .collect();

        let mut results: Vec<CertResult> = handles
            .into_iter()
            .map(|h| h.join().expect("scan thread panicked"))
            .collect();

        results.sort_by_key(|r| match &r.status {
            Status::Ok(days) => *days,
            Status::Error(_) => i64::MAX,
        });
        results
    });
    (handle, progress)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target_splits_host_and_port() {
        let t = parse_target("example.com:8443").unwrap();
        assert_eq!(t.host, "example.com");
        assert_eq!(t.port, 8443);
    }

    #[test]
    fn parse_target_defaults_to_443_without_a_port() {
        let t = parse_target("example.com").unwrap();
        assert_eq!(t.host, "example.com");
        assert_eq!(t.port, 443);
    }

    #[test]
    fn parse_target_skips_blank_and_comment_lines() {
        assert!(parse_target("").is_none());
        assert!(parse_target("   ").is_none());
        assert!(parse_target("# a comment").is_none());
    }

    #[test]
    fn parse_target_handles_ipv6_with_port() {
        let t = parse_target("[::1]:443").unwrap();
        assert_eq!(t.port, 443);
        assert!(t.host.contains("::1"));
    }

    #[test]
    fn check_target_reports_an_error_for_an_unroutable_host() {
        let target = Target {
            host: "127.0.0.1".to_string(),
            port: 1, // nothing listens here
        };
        let config = tls_config();
        let result = check_target(&target, Duration::from_millis(500), &config);
        assert!(matches!(result.status, Status::Error(_)));
    }
}

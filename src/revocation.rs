//! CRL-based revocation checking for every certificate in a presented chain.
//!
//! The rule is simple: only say "OK" when a CRL for every certificate was
//! fetched, its signature was verified against that certificate's issuer,
//! and the serial was not on it. Anything we could not check becomes
//! `Unknown` with a reason — never a silent OK.
//!
//! Trust model: we never trust the server's chain or an HTTP download on its
//! own. For each certificate we find an issuer public key (from the chain,
//! from the Mozilla root store in `webpki-roots`, or from the certificate's
//! AIA "CA Issuers" URL) and *verify that the certificate's own signature was
//! made by that key*. Only then do we use that key to verify the CRL. A
//! tampered CRL or a fake issuer certificate fails one of these signature
//! checks and gives `Unknown`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use x509_parser::oid_registry::{
    OID_PKIX_ACCESS_DESCRIPTOR_CA_ISSUERS, OID_X509_EXT_DELTA_CRL_INDICATOR,
};
use x509_parser::prelude::*;

/// Time limit to connect to a CRL server and to get the response headers.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
/// Total time limit for one download. Longer than `FETCH_TIMEOUT` because
/// some public CRLs are tens of MB (SSL.com's is about 40 MB).
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);
/// Largest CRL we are willing to download.
const MAX_DOWNLOAD_BYTES: u64 = 128 * 1024 * 1024;
/// Re-download a CRL at least this often, even if its nextUpdate is later,
/// so a long-running `--serve` or `--interval` session picks up new
/// revocations within an hour.
const CRL_MAX_AGE: Duration = Duration::from_secs(60 * 60);
/// Don't re-download more often than this, even if nextUpdate has passed.
const MIN_AGE: Duration = Duration::from_secs(5 * 60);
/// How long to remember a failed download before trying again.
const FAILURE_TTL: Duration = Duration::from_secs(5 * 60);
/// Issuer certificates fetched over AIA change rarely.
const ISSUER_CERT_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// Result of the revocation check for one target.
#[derive(Debug, Clone, PartialEq)]
pub enum Revocation {
    /// The check was turned off (`--no-revocation`) or did not apply (the
    /// connection itself failed).
    NotChecked,
    /// Every certificate in the chain was checked against a verified CRL.
    Ok,
    /// A certificate in the chain is on its issuer's CRL.
    Revoked {
        /// "leaf" or "intermediate #N" (position in the presented chain).
        which: String,
        subject: String,
        /// Revocation date, `YYYY-MM-DD`.
        date: String,
        reason: Option<String>,
    },
    /// The check could not be completed; the string says why.
    Unknown(String),
}

impl Revocation {
    pub fn label(&self) -> &'static str {
        match self {
            Revocation::NotChecked => "-",
            Revocation::Ok => "OK",
            Revocation::Revoked { .. } => "REVOKED",
            Revocation::Unknown(_) => "UNKNOWN",
        }
    }

    /// One-line explanation for detail views and reports.
    pub fn detail(&self) -> String {
        match self {
            Revocation::NotChecked => "not checked".to_string(),
            Revocation::Ok => "not revoked (CRL checked for every certificate)".to_string(),
            Revocation::Revoked {
                which,
                subject,
                date,
                reason,
            } => {
                let reason = reason
                    .as_deref()
                    .map(|r| format!(", reason: {r}"))
                    .unwrap_or_default();
                format!("REVOKED: {which} ({subject}) revoked on {date}{reason}")
            }
            Revocation::Unknown(why) => format!("unknown: {why}"),
        }
    }
}

type Fetcher = dyn Fn(&str) -> Result<Vec<u8>, String> + Send + Sync;

struct CacheEntry {
    result: Result<Arc<Vec<u8>>, String>,
    expires: Instant,
}

/// Download cache keyed by URL, shared by all scan threads for the whole
/// run. Each URL has its own lock, so two targets that share a CRL wait for
/// one download instead of starting two.
pub struct UrlCache {
    entries: Mutex<HashMap<String, Arc<Mutex<Option<CacheEntry>>>>>,
    fetcher: Box<Fetcher>,
}

impl UrlCache {
    pub fn new(fetcher: Box<Fetcher>) -> UrlCache {
        UrlCache {
            entries: Mutex::new(HashMap::new()),
            fetcher,
        }
    }

    /// The process-wide cache that downloads over HTTP(S).
    pub fn global() -> &'static UrlCache {
        static CACHE: OnceLock<UrlCache> = OnceLock::new();
        CACHE.get_or_init(|| UrlCache::new(Box::new(http_get)))
    }

    /// Return the body at `url`, from cache if still fresh. `ttl` decides
    /// how long a successful download stays fresh.
    fn get(&self, url: &str, ttl: impl Fn(&[u8]) -> Duration) -> Result<Arc<Vec<u8>>, String> {
        let slot = {
            let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            Arc::clone(entries.entry(url.to_string()).or_default())
        };
        let mut slot = slot.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = slot.as_ref()
            && entry.expires > Instant::now()
        {
            return entry.result.clone();
        }
        let result = (self.fetcher)(url).map(Arc::new);
        let lifetime = match &result {
            Ok(body) => ttl(body),
            Err(_) => FAILURE_TTL,
        };
        *slot = Some(CacheEntry {
            result: result.clone(),
            expires: Instant::now() + lifetime,
        });
        result
    }
}

fn http_get(url: &str) -> Result<Vec<u8>, String> {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    let agent = AGENT.get_or_init(|| {
        // Use the same crypto provider as the main TLS client, so the
        // process never has two rustls providers fighting over the default.
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let tls = ureq::tls::TlsConfig::builder()
            .provider(ureq::tls::TlsProvider::Rustls)
            .root_certs(ureq::tls::RootCerts::WebPki)
            .unversioned_rustls_crypto_provider(provider)
            .build();
        ureq::Agent::config_builder()
            .timeout_connect(Some(FETCH_TIMEOUT))
            .timeout_recv_response(Some(FETCH_TIMEOUT))
            .timeout_global(Some(DOWNLOAD_TIMEOUT))
            .http_status_as_error(true)
            .tls_config(tls)
            .user_agent(concat!("certmonitor/", env!("CARGO_PKG_VERSION")))
            .build()
            .into()
    });
    let mut response = agent
        .get(url)
        .call()
        .map_err(|e| format!("download of {url} failed: {e}"))?;
    response
        .body_mut()
        .with_config()
        .limit(MAX_DOWNLOAD_BYTES)
        .read_to_vec()
        .map_err(|e| format!("download of {url} failed: {e}"))
}

/// Accept DER as-is, or decode the first PEM block.
fn to_der(body: &[u8]) -> Result<Vec<u8>, String> {
    let trimmed = body
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .map(|i| &body[i..])
        .unwrap_or(body);
    if trimmed.starts_with(b"-----BEGIN") {
        let (_, pem) =
            x509_parser::pem::parse_x509_pem(trimmed).map_err(|e| format!("bad PEM data: {e}"))?;
        Ok(pem.contents)
    } else {
        Ok(body.to_vec())
    }
}

fn format_date(t: ASN1Time) -> String {
    let dt = t.to_datetime();
    format!("{:04}-{:02}-{:02}", dt.year(), dt.month() as u8, dt.day())
}

fn reason_name(code: u8) -> String {
    match code {
        0 => "unspecified",
        1 => "keyCompromise",
        2 => "cACompromise",
        3 => "affiliationChanged",
        4 => "superseded",
        5 => "cessationOfOperation",
        6 => "certificateHold",
        8 => "removeFromCRL",
        9 => "privilegeWithdrawn",
        10 => "aACompromise",
        _ => return format!("reason code {code}"),
    }
    .to_string()
}

/// Freshness for a downloaded CRL: until nextUpdate, but at most an hour
/// and at least a few minutes.
fn crl_ttl(body: &[u8]) -> Duration {
    let next_update = to_der(body).ok().and_then(|der| {
        CertificateRevocationList::from_der(&der)
            .ok()
            .and_then(|(_, crl)| crl.next_update())
            .map(|t| t.timestamp())
    });
    match next_update {
        Some(ts) => {
            let left = ts - ASN1Time::now().timestamp();
            Duration::from_secs(left.max(0) as u64).clamp(MIN_AGE, CRL_MAX_AGE)
        }
        None => CRL_MAX_AGE,
    }
}

fn http_urls<'a>(names: &'a [GeneralName<'a>]) -> impl Iterator<Item = &'a str> {
    names.iter().filter_map(|n| match n {
        GeneralName::URI(u) if u.starts_with("http://") || u.starts_with("https://") => Some(*u),
        _ => None,
    })
}

/// CRL Distribution Point URLs (http/https only). Points with a separate
/// cRLIssuer (indirect CRLs) are skipped: we can't verify those.
fn crl_urls(cert: &X509Certificate) -> Vec<String> {
    let mut urls = Vec::new();
    for ext in cert.extensions() {
        if let ParsedExtension::CRLDistributionPoints(points) = ext.parsed_extension() {
            for point in points.iter() {
                if point.crl_issuer.is_some() {
                    continue;
                }
                if let Some(DistributionPointName::FullName(names)) = &point.distribution_point {
                    urls.extend(http_urls(names).map(str::to_string));
                }
            }
        }
    }
    urls
}

fn ca_issuer_urls(cert: &X509Certificate) -> Vec<String> {
    let mut urls = Vec::new();
    for ext in cert.extensions() {
        if let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() {
            for desc in aia.iter() {
                if desc.access_method == OID_PKIX_ACCESS_DESCRIPTOR_CA_ISSUERS
                    && let GeneralName::URI(u) = &desc.access_location
                    && (u.starts_with("http://") || u.starts_with("https://"))
                {
                    urls.push(u.to_string());
                }
            }
        }
    }
    urls
}

/// `issuer` really issued `cert`: names match and `cert` carries a valid
/// signature from `issuer`'s key.
fn issued_by(cert: &X509Certificate, issuer: &X509Certificate) -> bool {
    cert.issuer() == issuer.subject() && cert.verify_signature(Some(issuer.public_key())).is_ok()
}

fn is_self_signed(cert: &X509Certificate) -> bool {
    cert.subject() == cert.issuer() && cert.verify_signature(None).is_ok()
}

/// Wrap DER *contents* in a SEQUENCE header. `webpki-roots` stores the
/// subject and SPKI of each root without their outer SEQUENCE.
fn wrap_sequence(contents: &[u8]) -> Vec<u8> {
    let len = contents.len();
    let mut out = vec![0x30];
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
    out.extend_from_slice(contents);
    out
}

/// Look for `cert`'s issuer among the Mozilla roots. Returns the root's
/// SPKI (DER) if a root with the right name signed `cert`.
fn find_root_issuer(cert: &X509Certificate) -> Option<Vec<u8>> {
    let issuer_name = cert.issuer().as_raw();
    webpki_roots::TLS_SERVER_ROOTS.iter().find_map(|anchor| {
        if wrap_sequence(anchor.subject.as_ref()) != issuer_name {
            return None;
        }
        let spki = wrap_sequence(anchor.subject_public_key_info.as_ref());
        let (_, key) = SubjectPublicKeyInfo::from_der(&spki).ok()?;
        cert.verify_signature(Some(&key))
            .is_ok()
            .then(|| spki.clone())
    })
}

/// `cert` carries the same name and key as a Mozilla root, so clients treat
/// it as a trust anchor (this matches a root's cross-signed copy too).
fn is_trust_anchor(cert: &X509Certificate) -> bool {
    let name = cert.subject().as_raw();
    let spki = cert.public_key().raw;
    webpki_roots::TLS_SERVER_ROOTS.iter().any(|anchor| {
        wrap_sequence(anchor.subject.as_ref()) == name
            && wrap_sequence(anchor.subject_public_key_info.as_ref()) == spki
    })
}

/// Find the public key (SPKI, DER) that signed `cert`: from the presented
/// chain, then the Mozilla root store, then via AIA. The key's signature
/// over `cert` is always verified before it is returned.
fn find_issuer_key(
    cert: &X509Certificate,
    chain: &[X509Certificate],
    cache: &UrlCache,
) -> Result<Vec<u8>, String> {
    if let Some(issuer) = chain.iter().find(|c| issued_by(cert, c)) {
        return Ok(issuer.public_key().raw.to_vec());
    }
    if let Some(spki) = find_root_issuer(cert) {
        return Ok(spki);
    }
    let urls = ca_issuer_urls(cert);
    if urls.is_empty() {
        return Err(
            "issuer certificate is not in the chain, not a known root, and has no AIA URL"
                .to_string(),
        );
    }
    let mut last_err = String::new();
    for url in urls {
        let body = match cache.get(&url, |_| ISSUER_CERT_MAX_AGE) {
            Ok(b) => b,
            Err(e) => {
                last_err = e;
                continue;
            }
        };
        let der = match to_der(&body) {
            Ok(d) => d,
            Err(e) => {
                last_err = format!("issuer certificate from {url}: {e}");
                continue;
            }
        };
        match X509Certificate::from_der(&der) {
            Ok((_, issuer)) if issued_by(cert, &issuer) => {
                return Ok(issuer.public_key().raw.to_vec());
            }
            Ok(_) => last_err = format!("issuer certificate from {url} did not sign the cert"),
            Err(e) => {
                last_err = format!("issuer certificate from {url} is not a DER/PEM cert: {e}")
            }
        }
    }
    Err(last_err)
}

/// What one CRL said about one certificate.
enum CrlVerdict {
    Good,
    Revoked {
        date: String,
        reason: Option<String>,
    },
}

/// Check `cert` against the CRL in `body`, which must be signed by
/// `issuer_key` (the verified key that signed `cert`).
fn check_against_crl(
    cert: &X509Certificate,
    issuer_key: &SubjectPublicKeyInfo,
    body: &[u8],
) -> Result<CrlVerdict, String> {
    let der = to_der(body)?;
    let (_, crl) =
        CertificateRevocationList::from_der(&der).map_err(|e| format!("CRL parse error: {e}"))?;
    if crl.issuer() != cert.issuer() {
        return Err("CRL issuer name does not match the certificate issuer".to_string());
    }
    crl.verify_signature(issuer_key)
        .map_err(|e| format!("CRL signature could not be verified: {e}"))?;
    if crl
        .extensions()
        .iter()
        .any(|e| e.oid == OID_X509_EXT_DELTA_CRL_INDICATOR)
    {
        return Err("CRL is a delta CRL (not supported)".to_string());
    }
    for ext in crl.extensions() {
        if let ParsedExtension::IssuingDistributionPoint(idp) = ext.parsed_extension() {
            let is_ca = cert.is_ca();
            if idp.indirect_crl
                || idp.only_some_reasons.is_some()
                || idp.only_contains_attribute_certs
                || (idp.only_contains_ca_certs && !is_ca)
                || (idp.only_contains_user_certs && is_ca)
            {
                return Err("CRL is partitioned in a way that does not cover this cert".to_string());
            }
        }
    }

    if let Some(entry) = crl
        .iter_revoked_certificates()
        .find(|r| r.user_certificate == cert.serial)
    {
        return Ok(CrlVerdict::Revoked {
            date: format_date(entry.revocation_date),
            reason: entry.reason_code().map(|(_, code)| reason_name(code.0)),
        });
    }

    if let Some(next) = crl.next_update()
        && next.timestamp() < ASN1Time::now().timestamp()
    {
        return Err(format!(
            "CRL is out of date (nextUpdate {})",
            format_date(next)
        ));
    }
    Ok(CrlVerdict::Good)
}

fn position_name(i: usize) -> String {
    if i == 0 {
        "leaf".to_string()
    } else {
        format!("intermediate #{i}")
    }
}

/// Check one certificate. `Ok(None)` = not revoked.
fn check_one(
    i: usize,
    cert: &X509Certificate,
    chain: &[X509Certificate],
    cache: &UrlCache,
) -> Result<Option<Revocation>, String> {
    let which = position_name(i);
    let urls = crl_urls(cert);
    if urls.is_empty() {
        return Err(format!("{which} has no http(s) CRL distribution point"));
    }
    let issuer_spki =
        find_issuer_key(cert, chain, cache).map_err(|e| format!("{which}: unverified: {e}"))?;
    let (_, issuer_key) = SubjectPublicKeyInfo::from_der(&issuer_spki)
        .map_err(|e| format!("{which}: issuer key parse error: {e}"))?;

    let mut last_err = String::new();
    for url in urls {
        let body = match cache.get(&url, crl_ttl) {
            Ok(b) => b,
            Err(e) => {
                last_err = e;
                continue;
            }
        };
        match check_against_crl(cert, &issuer_key, &body) {
            Ok(CrlVerdict::Good) if cert.validity().time_to_expiration().is_none() => {
                // CAs drop expired certs from their CRLs, so "not listed"
                // means nothing here.
                return Err(format!(
                    "{which} is expired, and CRLs do not list expired certificates"
                ));
            }
            Ok(CrlVerdict::Good) => return Ok(None),
            Ok(CrlVerdict::Revoked { date, reason }) => {
                return Ok(Some(Revocation::Revoked {
                    which,
                    subject: cert.subject().to_string(),
                    date,
                    reason,
                }));
            }
            Err(e) => last_err = format!("{e} ({url})"),
        }
    }
    Err(format!("{which}: {last_err}"))
}

/// Check the leaf and every intermediate on its issuer path in `chain_der`
/// (leaf first, as the server sent it).
pub fn check_chain(chain_der: &[&[u8]], cache: &UrlCache) -> Revocation {
    let mut chain = Vec::with_capacity(chain_der.len());
    for der in chain_der {
        match X509Certificate::from_der(der) {
            Ok((_, cert)) => chain.push(cert),
            Err(e) => return Revocation::Unknown(format!("certificate parse error: {e}")),
        }
    }
    if chain.is_empty() {
        return Revocation::Unknown("empty certificate chain".to_string());
    }

    if is_self_signed(&chain[0]) {
        return Revocation::Unknown("leaf is self-signed; there is no CRL to check".to_string());
    }

    // Walk the issuer path from the leaf through the presented chain. Stop
    // at a root (self-signed, or the same name and key as a Mozilla root):
    // revocation does not apply to roots, and certs above a trusted root
    // (old cross-signs) are not used by clients that trust that root.
    // Certs in the chain that are not on the path are ignored.
    let mut first_unknown = None;
    let mut visited = vec![false; chain.len()];
    let mut i = 0;
    loop {
        visited[i] = true;
        let cert = &chain[i];
        if i > 0 && (is_self_signed(cert) || is_trust_anchor(cert)) {
            break;
        }
        match check_one(i, cert, &chain, cache) {
            Ok(None) => {}
            Ok(Some(revoked)) => return revoked,
            Err(e) => {
                first_unknown.get_or_insert(e);
            }
        }
        match (0..chain.len()).find(|&j| !visited[j] && issued_by(cert, &chain[j])) {
            Some(next) => i = next,
            None => break,
        }
    }
    match first_unknown {
        Some(why) => Revocation::Unknown(why),
        None => Revocation::Ok,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, CertificateRevocationListParams, CrlDistributionPoint,
        DnType, IsCa, Issuer, KeyIdMethod, KeyPair, RevocationReason, RevokedCertParams,
        SerialNumber, date_time_ymd,
    };

    const CRL_URL: &str = "http://crl.test/ca.crl";

    struct Pki {
        ca_key: KeyPair,
        ca_params: CertificateParams,
        ca_der: Vec<u8>,
        leaf_der: Vec<u8>,
    }

    fn ca_params(name: &str) -> CertificateParams {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
    }

    fn make_pki() -> Pki {
        let ca_key = KeyPair::generate().unwrap();
        let ca_params = ca_params("Test CA");
        let ca_der = ca_params.self_signed(&ca_key).unwrap().der().to_vec();

        let leaf_key = KeyPair::generate().unwrap();
        let mut leaf_params = CertificateParams::new(vec!["leaf.test".to_string()]).unwrap();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "leaf.test");
        leaf_params.serial_number = Some(SerialNumber::from(vec![0x01, 0x02, 0x03]));
        leaf_params.crl_distribution_points = vec![CrlDistributionPoint {
            uris: vec![CRL_URL.to_string()],
        }];
        let issuer = Issuer::from_params(&ca_params, &ca_key);
        let leaf_der = leaf_params
            .signed_by(&leaf_key, &issuer)
            .unwrap()
            .der()
            .to_vec();
        Pki {
            ca_key,
            ca_params,
            ca_der,
            leaf_der,
        }
    }

    fn make_crl(
        params: &CertificateParams,
        key: &KeyPair,
        revoked_serials: &[Vec<u8>],
        pem: bool,
    ) -> Vec<u8> {
        let crl = CertificateRevocationListParams {
            this_update: date_time_ymd(2026, 1, 1),
            next_update: date_time_ymd(2099, 1, 1),
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: revoked_serials
                .iter()
                .map(|s| RevokedCertParams {
                    serial_number: SerialNumber::from(s.clone()),
                    revocation_time: date_time_ymd(2026, 10, 19),
                    reason_code: Some(RevocationReason::KeyCompromise),
                    invalidity_date: None,
                })
                .collect(),
            key_identifier_method: KeyIdMethod::Sha256,
        };
        let issuer = Issuer::from_params(params, key);
        let crl = crl.signed_by(&issuer).unwrap();
        if pem {
            crl.pem().unwrap().into_bytes()
        } else {
            crl.der().to_vec()
        }
    }

    fn cache_serving(body: Vec<u8>) -> UrlCache {
        UrlCache::new(Box::new(move |url| {
            if url == CRL_URL {
                Ok(body.clone())
            } else {
                Err(format!("no such URL {url}"))
            }
        }))
    }

    #[test]
    fn revoked_serial_is_reported() {
        let pki = make_pki();
        let crl = make_crl(
            &pki.ca_params,
            &pki.ca_key,
            &[vec![0x01, 0x02, 0x03]],
            false,
        );
        let cache = cache_serving(crl);
        let result = check_chain(&[&pki.leaf_der, &pki.ca_der], &cache);
        match result {
            Revocation::Revoked {
                which,
                date,
                reason,
                ..
            } => {
                assert_eq!(which, "leaf");
                assert_eq!(date, "2026-10-19");
                assert_eq!(reason.as_deref(), Some("keyCompromise"));
            }
            other => panic!("expected Revoked, got {other:?}"),
        }
    }

    #[test]
    fn serial_not_on_crl_is_ok_and_pem_is_accepted() {
        let pki = make_pki();
        let crl = make_crl(&pki.ca_params, &pki.ca_key, &[vec![0x09, 0x09]], true);
        let cache = cache_serving(crl);
        assert_eq!(
            check_chain(&[&pki.leaf_der, &pki.ca_der], &cache),
            Revocation::Ok
        );
    }

    #[test]
    fn crl_signed_by_wrong_key_is_unknown() {
        let pki = make_pki();
        // Same issuer name, different key: looks right, but the signature
        // does not verify against the real CA key.
        let impostor_key = KeyPair::generate().unwrap();
        let crl = make_crl(&pki.ca_params, &impostor_key, &[], false);
        let cache = cache_serving(crl);
        let result = check_chain(&[&pki.leaf_der, &pki.ca_der], &cache);
        assert!(
            matches!(&result, Revocation::Unknown(why) if why.contains("signature")),
            "got {result:?}"
        );
    }

    #[test]
    fn corrupted_crl_is_unknown() {
        let pki = make_pki();
        let mut crl = make_crl(&pki.ca_params, &pki.ca_key, &[], false);
        let last = crl.len() - 1;
        crl[last] ^= 0xff; // flip bits in the signature
        let cache = cache_serving(crl);
        let result = check_chain(&[&pki.leaf_der, &pki.ca_der], &cache);
        assert!(matches!(result, Revocation::Unknown(_)), "got {result:?}");
    }

    #[test]
    fn missing_issuer_is_unknown_not_ok() {
        let pki = make_pki();
        let crl = make_crl(&pki.ca_params, &pki.ca_key, &[], false);
        let cache = cache_serving(crl);
        // Chain without the CA and no AIA URL: we cannot verify the CRL.
        let result = check_chain(&[&pki.leaf_der], &cache);
        assert!(
            matches!(&result, Revocation::Unknown(why) if why.contains("unverified")),
            "got {result:?}"
        );
    }

    #[test]
    fn fetch_failure_is_unknown() {
        let pki = make_pki();
        let cache = UrlCache::new(Box::new(|_| Err("connection refused".to_string())));
        let result = check_chain(&[&pki.leaf_der, &pki.ca_der], &cache);
        assert!(
            matches!(&result, Revocation::Unknown(why) if why.contains("connection refused")),
            "got {result:?}"
        );
    }

    #[test]
    fn cert_without_cdp_is_unknown() {
        let pki = make_pki();
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["nocdp.test".to_string()]).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "nocdp.test");
        let issuer = Issuer::from_params(&pki.ca_params, &pki.ca_key);
        let leaf = params.signed_by(&key, &issuer).unwrap().der().to_vec();
        let cache = cache_serving(Vec::new());
        let result = check_chain(&[&leaf, &pki.ca_der], &cache);
        assert!(
            matches!(&result, Revocation::Unknown(why) if why.contains("no http(s) CRL")),
            "got {result:?}"
        );
    }

    #[test]
    fn wrap_sequence_restores_der() {
        let pki = make_pki();
        let (_, ca) = X509Certificate::from_der(&pki.ca_der).unwrap();
        let name = ca.subject().as_raw();
        // Strip the 2-byte SEQUENCE header and put it back.
        assert_eq!(wrap_sequence(&name[2..]), name);
        let long = vec![0u8; 300];
        assert_eq!(&wrap_sequence(&long)[..4], &[0x30, 0x82, 0x01, 0x2c]);
    }

    #[test]
    fn downloads_are_cached_per_url() {
        let pki = make_pki();
        let crl = make_crl(&pki.ca_params, &pki.ca_key, &[], false);
        let count = Arc::new(Mutex::new(0));
        let counter = Arc::clone(&count);
        let cache = UrlCache::new(Box::new(move |_| {
            *counter.lock().unwrap() += 1;
            Ok(crl.clone())
        }));
        for _ in 0..3 {
            assert_eq!(
                check_chain(&[&pki.leaf_der, &pki.ca_der], &cache),
                Revocation::Ok
            );
        }
        assert_eq!(*count.lock().unwrap(), 1);
    }

    #[test]
    fn self_signed_leaf_is_unknown() {
        let pki = make_pki();
        let cache = cache_serving(Vec::new());
        assert!(matches!(
            check_chain(&[&pki.ca_der], &cache),
            Revocation::Unknown(_)
        ));
    }
}

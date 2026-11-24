//! Network names for legs (4.107).
//!
//! The server stamps each heartbeat PONG with the observed source
//! address; when the client asks for it (PINGs carrying
//! [`FLAG_NETWORK_NAME`](bonded_core::session::FLAG_NETWORK_NAME))
//! the PONG also carries the network name the server resolved for
//! that address: the ASN org (from a local copy of the iptoasn.com
//! combined TSV feed) and the PTR hostname (reverse DNS, cached).
//! The same resolver fills the peer-share introduction claims at
//! mint time, from each side's live session source IP.
//!
//! Design (recorded in the plan row):
//! - ASN data: two sorted tables (v4 as `u32` ranges, v6 as `u128`
//!   ranges) + binary search, org strings deduplicated. ~10 MB in
//!   memory. No maxminddb, no prebuilt MMDB. Parsed directly from
//!   the TSV (plain or gzip-compressed) in Rust, so auto-refresh is
//!   re-download + re-parse + swap.
//! - ASN lookup is a pure table lookup and never blocks. PTR uses
//!   hickory-resolver against the server's configured `dns_server`
//!   (192.168.1.1 on Dell) when set, else the system resolver
//!   config; 2 s timeout cap; a timeout / NXDOMAIN means "no PTR
//!   name", never an error.
//! - PTR is OFF the hot path: [`NetworkNameResolver::resolve`]
//!   does a cache/table read only. On a PTR cache miss it stamps
//!   the ASN name (PTR absent) and spawns a background resolution
//!   that fills the cache, so the PTR appears on a later pong.
//!   A pong is never blocked on DNS.
//! - Refresh ([`NetworkNameResolver::refresh`]) downloads to a temp
//!   file in the same directory, verifies before swapping (it
//!   parses, has a sane range count, and passes the known-IP sanity
//!   check 8.8.8.8 → AS15169 / "GOOGLE - Google LLC"), atomically
//!   renames over the live path, and swaps the in-memory table
//!   without a restart. On ANY failure the old data is kept.

use std::collections::HashMap;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context};
use bonded_core::config::{ServerSection, DEFAULT_ASN_DB_URL};

/// PTR cache time-to-live: a resolved (or missing) PTR name is
/// re-looked-up at most once an hour per IP.
pub const PTR_CACHE_TTL: Duration = Duration::from_secs(3600);
/// Hard cap on a single PTR lookup: slower than this means "no PTR
/// name", never a stalled pong or a stalled refresh.
pub const PTR_LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);
/// Known-IP sanity check for a freshly parsed table: 8.8.8.8 must
/// resolve to AS15169 with an org starting with "GOOGLE".
pub const ASN_SANITY_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8));
pub const ASN_SANITY_ASN: u32 = 15_169;
/// Minimum routed-range count for a table to be trusted: the live
/// feed carries ~580k routed ranges (719k lines minus ~140k
/// AS-0 "Not routed" rows), so anything under 100k is a truncated
/// or wrong file, not a feed.
pub const ASN_MIN_SANE_RANGES: usize = 100_000;

/// The network name of one public IP, as the server resolved it.
/// Either half may be absent: absent is explicit unknown, never
/// an invented name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkName {
    /// ASN org description, e.g. `"GOOGLE - Google LLC"`.
    pub asn_org: Option<String>,
    /// PTR hostname, e.g. `"dns.google"` (trailing dot stripped).
    pub ptr_hostname: Option<String>,
}

#[derive(Debug, Clone)]
struct AsnRange {
    start: u128,
    end: u128,
    asn: u32,
    org: u32,
}

/// Parsed ASN tables: one sorted, non-overlapping range list per
/// address family, plus the deduplicated org strings they index
/// into.
#[derive(Debug, Default)]
pub struct AsnTables {
    v4: Vec<AsnRange>,
    v6: Vec<AsnRange>,
    orgs: Vec<String>,
}

impl AsnTables {
    /// ASN org name for `ip`, or `None` when the address falls in
    /// no routed range (including AS-0 "Not routed" rows, which
    /// are dropped at parse time).
    pub fn lookup(&self, ip: IpAddr) -> Option<&str> {
        let (table, key) = match ip {
            IpAddr::V4(ip) => (&self.v4, u128::from(u32::from(ip))),
            IpAddr::V6(ip) => (&self.v6, u128::from(ip)),
        };
        // Ranges are sorted by start and non-overlapping, so the
        // last range starting at or before the key is the only
        // candidate.
        let idx = table.partition_point(|range| range.start <= key);
        let range = table.get(idx.checked_sub(1)?)?;
        if key <= range.end {
            self.orgs.get(range.org as usize).map(String::as_str)
        } else {
            None
        }
    }

    /// ASN number for `ip`, or `None` when unrouted. Used by the
    /// sanity check (org strings alone could collide).
    pub fn lookup_asn(&self, ip: IpAddr) -> Option<u32> {
        let (table, key) = match ip {
            IpAddr::V4(ip) => (&self.v4, u128::from(u32::from(ip))),
            IpAddr::V6(ip) => (&self.v6, u128::from(ip)),
        };
        let idx = table.partition_point(|range| range.start <= key);
        let range = table.get(idx.checked_sub(1)?)?;
        if key <= range.end {
            Some(range.asn)
        } else {
            None
        }
    }

    pub fn range_count(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.range_count() == 0
    }

    /// Parse an iptoasn.com combined TSV feed: tab-separated
    /// `range_start, range_end, AS_number, country_code,
    /// AS_description`, v4 ranges first, then v6, sorted by range
    /// start. `reader` may be the plain TSV or the gzip-compressed
    /// feed (detected by the gzip magic bytes). AS-0 / "Not routed"
    /// rows are dropped: they mean "no ASN name", not a name.
    pub fn parse_reader(reader: impl Read) -> anyhow::Result<Self> {
        let mut bytes = Vec::new();
        let mut reader = reader;
        reader
            .read_to_end(&mut bytes)
            .context("failed to read ASN database")?;
        let text = if bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b {
            let mut decoder = flate2::read::GzDecoder::new(&bytes[..]);
            let mut plain = String::new();
            decoder
                .read_to_string(&mut plain)
                .context("failed to gunzip ASN database")?;
            plain
        } else {
            String::from_utf8(bytes).context("ASN database is not valid UTF-8")?
        };
        Self::parse_str(&text)
    }

    fn parse_str(text: &str) -> anyhow::Result<Self> {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        let mut orgs: Vec<String> = Vec::new();
        let mut org_index: HashMap<String, u32> = HashMap::new();
        for (line_no, line) in text.lines().enumerate() {
            let line = line.trim_end_matches(['\r', '\n']);
            if line.is_empty() {
                continue;
            }
            let mut cols = line.split('\t');
            let start = cols.next().unwrap_or("");
            let end = cols.next().unwrap_or("");
            let asn = cols.next().unwrap_or("");
            let _country = cols.next().unwrap_or("");
            let org = cols.next().unwrap_or("");
            let start_ip: IpAddr = start.parse().with_context(|| {
                format!("ASN database line {}: bad range start {start:?}", line_no + 1)
            })?;
            let end_ip: IpAddr = end.parse().with_context(|| {
                format!("ASN database line {}: bad range end {end:?}", line_no + 1)
            })?;
            let asn: u32 = asn.parse().with_context(|| {
                format!("ASN database line {}: bad AS number {asn:?}", line_no + 1)
            })?;
            // AS 0 / "Not routed" means unrouted: no name, and the
            // range must not shadow a routed one.
            if asn == 0 || org == "Not routed" {
                continue;
            }
            if org.is_empty() {
                continue;
            }
            let org_idx = *org_index.entry(org.to_owned()).or_insert_with(|| {
                orgs.push(org.to_owned());
                (orgs.len() - 1) as u32
            });
            let range = AsnRange {
                start: ip_to_u128(start_ip),
                end: ip_to_u128(end_ip),
                asn,
                org: org_idx,
            };
            match (start_ip, end_ip) {
                (IpAddr::V4(_), IpAddr::V4(_)) => v4.push(range),
                (IpAddr::V6(_), IpAddr::V6(_)) => v6.push(range),
                _ => {
                    anyhow::bail!(
                        "ASN database line {}: mixed-family range {start:?} - {end:?}",
                        line_no + 1
                    );
                }
            }
        }
        // The feed is sorted, but sort defensively: the binary
        // search below is only correct on sorted input, and a
        // re-sort of an already-sorted table is free.
        v4.sort_by_key(|range| range.start);
        v6.sort_by_key(|range| range.start);
        let tables = Self { v4, v6, orgs };
        if tables.is_empty() {
            anyhow::bail!("ASN database parsed to zero routed ranges");
        }
        Ok(tables)
    }

    /// Load a feed file from disk (plain TSV or `.gz`).
    pub fn load_file(path: &Path) -> anyhow::Result<Self> {
        let file = std::fs::File::open(path)
            .with_context(|| format!("failed to open ASN database {}", path.display()))?;
        Self::parse_reader(std::io::BufReader::new(file))
    }

    /// Sanity check for a freshly parsed table: the known IP
    /// 8.8.8.8 must resolve to AS15169 with a GOOGLE org, and the
    /// table must carry a sane number of routed ranges.
    pub fn verify_sanity(&self) -> anyhow::Result<()> {
        if self.range_count() < ASN_MIN_SANE_RANGES {
            anyhow::bail!(
                "ASN database sanity check failed: only {} routed ranges (minimum {})",
                self.range_count(),
                ASN_MIN_SANE_RANGES
            );
        }
        match self.lookup_asn(ASN_SANITY_IP) {
            Some(ASN_SANITY_ASN) => {}
            other => {
                anyhow::bail!(
                    "ASN database sanity check failed: 8.8.8.8 resolved to AS {other:?}, expected AS {ASN_SANITY_ASN}"
                );
            }
        }
        match self.lookup(ASN_SANITY_IP) {
            Some(org) if org.starts_with("GOOGLE") => Ok(()),
            other => anyhow::bail!(
                "ASN database sanity check failed: 8.8.8.8 org is {other:?}, expected a GOOGLE org"
            ),
        }
    }
}

fn ip_to_u128(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(ip) => u128::from(u32::from(ip)),
        IpAddr::V6(ip) => u128::from(ip),
    }
}

/// Whether `ip` is a globally routable address. (`IpAddr::is_global`
/// is still unstable, so this spells it out with the stable
/// per-family helpers: anything private, loopback, link-local,
/// documentation, benchmarking, reserved, shared/CGNAT, multicast
/// or unspecified is not global.)
fn is_global_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let o = ip.octets();
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_broadcast()
                && !ip.is_multicast()
                && !ip.is_unspecified()
                && !ip.is_documentation()
                && !(o[0] == 198 && (18..=19).contains(&o[1]))
                && o[0] < 240
                && !(o[0] == 100 && (64..=127).contains(&o[1]))
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            !ip.is_loopback()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && segments[0] & 0xffc0 != 0xfe80
                && segments[0] & 0xfe00 != 0xfc00
                && !(segments[0] == 0x2001 && (segments[1] == 0x0002 || segments[1] == 0x0db8))
        }
    }
}

#[derive(Debug, Clone)]
struct PtrCacheEntry {
    name: Option<String>,
    at: Instant,
}

/// Report for a successful ASN table refresh (4.107): the range
/// counts before and after the swap, for the log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefreshReport {
    pub old_range_count: usize,
    pub new_range_count: usize,
}

/// Owns the ASN tables, the PTR cache, and the refresh settings
/// (4.107). Cheap to clone behind an `Arc`: the tables swap
/// atomically under a read-write lock, so lookups never block on a
/// refresh and a refresh never blocks lookups.
#[derive(Debug)]
pub struct NetworkNameResolver {
    tables: RwLock<Arc<AsnTables>>,
    ptr_cache: Mutex<HashMap<IpAddr, PtrCacheEntry>>,
    ptr_enabled: bool,
    /// Upstream resolver for PTR lookups (the server's configured
    /// `dns_server`, e.g. 192.168.1.1). `None` = system resolver
    /// config.
    dns_server: Option<IpAddr>,
    db_path: Option<PathBuf>,
    db_url: String,
    refresh_interval: Duration,
}

impl NetworkNameResolver {
    /// Build a resolver from the server config: load the ASN file
    /// when `asn_db_path` is set (a load failure is logged and
    /// leaves the tables empty — ASN lookup disabled, PTR still
    /// works — never a startup failure).
    pub fn from_config(cfg: &ServerSection) -> Arc<Self> {
        let tables = match cfg.asn_db_path.as_deref() {
            Some(path) => match AsnTables::load_file(Path::new(path)) {
                Ok(tables) => {
                    tracing::info!(
                        path = %path,
                        ranges = tables.range_count(),
                        "ASN database loaded"
                    );
                    Arc::new(tables)
                }
                Err(err) => {
                    tracing::warn!(
                        path = %path,
                        error = %err,
                        "failed to load ASN database; ASN lookup disabled until a refresh succeeds"
                    );
                    Arc::new(AsnTables::default())
                }
            },
            None => Arc::new(AsnTables::default()),
        };
        Arc::new(Self {
            tables: RwLock::new(tables),
            ptr_cache: Mutex::new(HashMap::new()),
            ptr_enabled: cfg.ptr_lookup,
            dns_server: cfg
                .dns_server_addr()
                .ok()
                .map(|addr| addr.ip()),
            db_path: cfg.asn_db_path.clone().map(PathBuf::from),
            db_url: cfg.asn_db_url_or_default().to_owned(),
            refresh_interval: Duration::from_secs(cfg.asn_db_refresh_interval_secs),
        })
    }

    /// Build a resolver over already-parsed tables (tests, and
    /// callers that loaded the file themselves).
    pub fn with_tables(
        tables: AsnTables,
        ptr_enabled: bool,
        dns_server: Option<IpAddr>,
    ) -> Arc<Self> {
        Arc::new(Self {
            tables: RwLock::new(Arc::new(tables)),
            ptr_cache: Mutex::new(HashMap::new()),
            ptr_enabled,
            dns_server,
            db_path: None,
            db_url: DEFAULT_ASN_DB_URL.to_owned(),
            refresh_interval: Duration::from_secs(86_400),
        })
    }

    /// Resolve `ip` to its network name. Cache/table read only:
    /// the ASN half is a pure table lookup, the PTR half is a cache
    /// lookup. On a PTR cache miss (and when PTR is enabled and the
    /// address is global) a background resolution is spawned that
    /// fills the cache, so the PTR appears on a later pong — this
    /// call never waits on DNS.
    pub fn resolve(self: &Arc<Self>, ip: IpAddr) -> NetworkName {
        let asn_org = self.asn_org(ip);
        let ptr_hostname = self.ptr_cached(ip).unwrap_or_else(|| {
            self.spawn_ptr_lookup(ip);
            None
        });
        NetworkName {
            asn_org,
            ptr_hostname,
        }
    }

    /// ASN org name for `ip`, or `None` when unrouted / no table.
    pub fn asn_org(&self, ip: IpAddr) -> Option<String> {
        let tables = self.tables.read().ok()?;
        tables.lookup(ip).map(str::to_owned)
    }

    /// Number of routed ranges in the live table (0 when no ASN
    /// database is loaded).
    pub fn range_count(&self) -> usize {
        self.tables
            .read()
            .map(|tables| tables.range_count())
            .unwrap_or(0)
    }

    /// Whether an ASN table is loaded at all.
    pub fn has_asn_data(&self) -> bool {
        self.range_count() > 0
    }

    pub fn db_path(&self) -> Option<&Path> {
        self.db_path.as_deref()
    }

    pub fn refresh_interval(&self) -> Duration {
        self.refresh_interval
    }

    pub fn auto_refresh_configured(&self) -> bool {
        self.db_path.is_some()
    }

    /// Cached PTR name for `ip`: `Some(name)` on a fresh cache hit
    /// (where `name` is `None` for a cached miss), `None` on a
    /// cache miss or an expired entry.
    fn ptr_cached(&self, ip: IpAddr) -> Option<Option<String>> {
        let cache = self.ptr_cache.lock().ok()?;
        let entry = cache.get(&ip)?;
        if entry.at.elapsed() > PTR_CACHE_TTL {
            return None;
        }
        Some(entry.name.clone())
    }

    /// Record a PTR result in the cache (called by the background
    /// lookup task, and by tests).
    pub(crate) fn cache_ptr(&self, ip: IpAddr, name: Option<String>) {
        if let Ok(mut cache) = self.ptr_cache.lock() {
            cache.insert(ip, PtrCacheEntry {
                name,
                at: Instant::now(),
            });
        }
    }

    /// Spawn the background PTR resolution for `ip`. No-op when
    /// PTR is disabled, the address is not global (a leg's public
    /// source IP is global by definition; LAN/loopback addresses
    /// have no meaningful PTR), or there is no tokio runtime in
    /// this context (e.g. a sync unit test — the PTR simply stays
    /// absent until a later pong from an async context triggers it).
    fn spawn_ptr_lookup(self: &Arc<Self>, ip: IpAddr) {
        if !self.ptr_enabled || !is_global_ip(ip) {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let this = Arc::clone(self);
        handle.spawn(async move {
            let name = this.ptr_lookup_once(ip).await;
            this.cache_ptr(ip, name);
        });
    }

    /// One PTR lookup against the configured upstream (or the
    /// system resolver config when none is set), capped at
    /// [`PTR_LOOKUP_TIMEOUT`]. Any failure — timeout, NXDOMAIN,
    /// unreachable upstream — means "no PTR name", never an error.
    async fn ptr_lookup_once(&self, ip: IpAddr) -> Option<String> {
        use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig};
        use hickory_resolver::name_server::TokioConnectionProvider;
        use hickory_resolver::Resolver;
        let build = || -> Option<Resolver<TokioConnectionProvider>> {
            match self.dns_server {
                Some(ns) => {
                    let config = ResolverConfig::from_parts(
                        None,
                        vec![],
                        NameServerConfigGroup::from_ips_clear(&[ns], 53, true),
                    );
                    Some(
                        Resolver::builder_with_config(
                            config,
                            TokioConnectionProvider::default(),
                        )
                        .build(),
                    )
                }
                None => Resolver::builder_tokio().ok().map(|builder| builder.build()),
            }
        };
        let resolver = build()?;
        let lookup = tokio::time::timeout(PTR_LOOKUP_TIMEOUT, resolver.reverse_lookup(ip))
            .await
            .ok()?
            .ok()?;
        let name = lookup.iter().next()?.to_string();
        let name = name.trim_end_matches('.').to_owned();
        if name.is_empty() {
            None
        } else {
            Some(name)
        }
    }

    /// Download the ASN feed, verify it, atomically replace the
    /// live file, and swap the in-memory table — without a restart.
    /// On ANY failure the old file and the old table are kept and
    /// the error is returned (the caller logs a warning and retries
    /// at the next interval). No-op error when no `asn_db_path` is
    /// configured: there is nowhere to store a download.
    pub async fn refresh(self: &Arc<Self>) -> anyhow::Result<RefreshReport> {
        let path = self
            .db_path
            .clone()
            .ok_or_else(|| anyhow!("ASN auto-refresh is on but no asn_db_path is configured"))?;
        let tmp_path = path.with_file_name(format!(
            ".{}-refresh.tmp",
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| "ip2asn.tsv.gz".to_owned())
        ));
        let outcome = self.refresh_inner(&path, &tmp_path).await;
        // The temp file must never linger, whatever failed.
        let _ = std::fs::remove_file(&tmp_path);
        let report = outcome?;
        tracing::info!(
            path = %path.display(),
            old_ranges = report.old_range_count,
            new_ranges = report.new_range_count,
            "ASN database refreshed"
        );
        Ok(report)
    }

    async fn refresh_inner(
        self: &Arc<Self>,
        path: &Path,
        tmp_path: &Path,
    ) -> anyhow::Result<RefreshReport> {
        let old_count = self.range_count();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .context("failed to build ASN download client")?;
        let response = client
            .get(self.db_url.clone())
            .send()
            .await
            .context("ASN database download failed")?
            .error_for_status()
            .context("ASN database download returned an error status")?;
        let bytes = response
            .bytes()
            .await
            .context("ASN database download body read failed")?;
        if bytes.len() < 1024 {
            anyhow::bail!(
                "ASN database download too small ({} bytes): not a feed",
                bytes.len()
            );
        }
        std::fs::write(tmp_path, &bytes).with_context(|| {
            format!("failed to write ASN database temp file {}", tmp_path.display())
        })?;
        // Parse + verify BEFORE touching the live file or table.
        let new_tables = tokio::task::spawn_blocking({
            let tmp_path = tmp_path.to_owned();
            move || AsnTables::load_file(&tmp_path)
        })
        .await
        .context("ASN database parse task failed")??;
        new_tables.verify_sanity()?;
        std::fs::rename(tmp_path, path).with_context(|| {
            format!(
                "failed to atomically replace ASN database {}",
                path.display()
            )
        })?;
        {
            let mut guard = self
                .tables
                .write()
                .map_err(|_| anyhow!("ASN table lock poisoned"))?;
            *guard = Arc::new(new_tables);
        }
        Ok(RefreshReport {
            old_range_count: old_count,
            new_range_count: self.range_count(),
        })
    }

    /// Verify a candidate file and swap it in as the live table
    /// (used by [`NetworkNameResolver::refresh`] after a download,
    /// and directly by tests of the swap logic). The caller owns
    /// the file placement: on success the table is swapped; on
    /// failure the old table is kept untouched.
    pub fn swap_from_file(&self, path: &Path) -> anyhow::Result<RefreshReport> {
        let old_count = self.range_count();
        let new_tables = AsnTables::load_file(path)?;
        new_tables.verify_sanity()?;
        {
            let mut guard = self
                .tables
                .write()
                .map_err(|_| anyhow!("ASN table lock poisoned"))?;
            *guard = Arc::new(new_tables);
        }
        Ok(RefreshReport {
            old_range_count: old_count,
            new_range_count: self.range_count(),
        })
    }
}

/// Build a heartbeat PONG payload for the transport peer at
/// `peer` (4.107). When the PING carried
/// [`FLAG_NETWORK_NAME`](bonded_core::session::FLAG_NETWORK_NAME)
/// and a resolver is configured, the payload is the EXTENDED
/// format — observed address plus the ASN org and PTR hostname
/// resolved for it; otherwise it is the plain address-only
/// payload, exactly as before. Old clients never set the flag, so
/// they see zero change; a server without a resolver always sends
/// the plain format. Every PONG stamp site (WSS, QUIC, NaiveTCP)
/// funnels through this one function so the formats cannot drift.
pub fn observed_pong_payload(
    resolver: Option<&Arc<NetworkNameResolver>>,
    peer: std::net::SocketAddr,
    wants_network_name: bool,
) -> bytes::Bytes {
    use bonded_core::session::{encode_observed_address, encode_observed_network};
    match (wants_network_name, resolver) {
        (true, Some(resolver)) => {
            let name = resolver.resolve(peer.ip());
            encode_observed_network(
                peer,
                name.asn_org.as_deref(),
                name.ptr_hostname.as_deref(),
            )
        }
        _ => encode_observed_address(peer),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Small synthetic feed covering the exact IPs the design
    /// spot-checks, plus an unrouted range and a v6 range. (The
    /// live feed is verified separately by `real_feed_spot_check`,
    /// ignored by default: it needs the downloaded file.)
    fn synthetic_tsv() -> &'static str {
        "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET - Cloudflare, Inc.\n\
         1.0.1.0\t1.0.1.255\t0\tZZ\tNot routed\n\
         8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE - Google LLC\n\
         2001:4860:4860::\t2001:4860:4860:ffff:ffff:ffff:ffff:ffff\t15169\tUS\tGOOGLE - Google LLC\n"
    }

    fn synthetic_tables() -> AsnTables {
        AsnTables::parse_reader(Cursor::new(synthetic_tsv()))
            .expect("synthetic feed should parse")
    }

    #[test]
    fn is_global_ip_classifies_public_vs_private_addresses() {
        assert!(is_global_ip("8.8.8.8".parse().unwrap()));
        assert!(is_global_ip("2001:4860:4860::8888".parse().unwrap()));
        assert!(!is_global_ip("192.168.1.1".parse().unwrap()));
        assert!(!is_global_ip("10.0.0.1".parse().unwrap()));
        assert!(!is_global_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_global_ip("169.254.1.1".parse().unwrap()));
        assert!(!is_global_ip("100.64.0.1".parse().unwrap()));
        assert!(!is_global_ip("::1".parse().unwrap()));
        assert!(!is_global_ip("fe80::1".parse().unwrap()));
        assert!(!is_global_ip("fd00::1".parse().unwrap()));
        assert!(!is_global_ip("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn asn_lookup_spot_checks_match_the_live_feed_values() {
        let tables = synthetic_tables();
        assert_eq!(tables.range_count(), 3);
        assert_eq!(
            tables.lookup("8.8.8.8".parse().unwrap()),
            Some("GOOGLE - Google LLC")
        );
        assert_eq!(tables.lookup_asn("8.8.8.8".parse().unwrap()), Some(15_169));
        // 1.1.1.1 is NOT in the synthetic table's 1.0.0.0/24 row,
        // so it is unrouted here (the live feed has its own
        // 1.1.1.0/24 row; see real_feed_spot_check).
        assert_eq!(tables.lookup("1.1.1.1".parse().unwrap()), None);
        assert_eq!(
            tables.lookup("1.0.0.1".parse().unwrap()),
            Some("CLOUDFLARENET - Cloudflare, Inc.")
        );
        // AS-0 "Not routed" rows carry no name.
        assert_eq!(tables.lookup("1.0.1.0".parse().unwrap()), None);
        assert_eq!(tables.lookup_asn("1.0.1.0".parse().unwrap()), None);
        // IPv6 range resolves to the same org.
        assert_eq!(
            tables.lookup("2001:4860:4860::8888".parse().unwrap()),
            Some("GOOGLE - Google LLC")
        );
        // Range boundaries are inclusive; outside is unrouted.
        assert_eq!(
            tables.lookup("8.8.8.0".parse().unwrap()),
            Some("GOOGLE - Google LLC")
        );
        assert_eq!(
            tables.lookup("8.8.8.255".parse().unwrap()),
            Some("GOOGLE - Google LLC")
        );
        assert_eq!(tables.lookup("8.8.9.0".parse().unwrap()), None);
        assert_eq!(tables.lookup("9.9.9.9".parse().unwrap()), None);
    }

    #[test]
    fn asn_gzipped_feed_parses_like_the_plain_feed() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(synthetic_tsv().as_bytes())
            .expect("gzip write should succeed");
        let gzipped = encoder.finish().expect("gzip finish should succeed");
        let tables =
            AsnTables::parse_reader(Cursor::new(gzipped)).expect("gzipped feed should parse");
        assert_eq!(tables.range_count(), 3);
        assert_eq!(
            tables.lookup("8.8.8.8".parse().unwrap()),
            Some("GOOGLE - Google LLC")
        );
    }

    #[test]
    fn asn_bad_or_truncated_file_fails_to_load() {
        // Garbage is not a feed.
        assert!(AsnTables::parse_reader(Cursor::new("not a feed at all")).is_err());
        // A truncated row (missing columns / bad AS number) fails.
        assert!(AsnTables::parse_reader(Cursor::new(
            "8.8.8.0\t8.8.8.255\tnot-a-number\tUS\tGOOGLE\n"
        ))
        .is_err());
        // An empty file parses to zero ranges: rejected, not an
        // empty table a caller could mistake for "no ASN data".
        assert!(AsnTables::parse_reader(Cursor::new("")).is_err());
        // A file of only AS-0 rows is equally empty.
        assert!(AsnTables::parse_reader(Cursor::new(
            "1.0.1.0\t1.0.1.255\t0\tZZ\tNot routed\n"
        ))
        .is_err());
    }

    #[test]
    fn resolver_returns_asn_name_and_no_ptr_without_a_runtime() {
        // In a sync test there is no tokio runtime, so no background
        // PTR spawn happens: resolve is a pure cache/table read and
        // the PTR half stays absent.
        let resolver = NetworkNameResolver::with_tables(synthetic_tables(), true, None);
        let name = resolver.resolve("8.8.8.8".parse().unwrap());
        assert_eq!(name.asn_org.as_deref(), Some("GOOGLE - Google LLC"));
        assert_eq!(name.ptr_hostname, None);
        let unrouted = resolver.resolve("1.0.1.0".parse().unwrap());
        assert_eq!(unrouted.asn_org, None);
        assert_eq!(unrouted.ptr_hostname, None);
    }

    #[test]
    fn resolver_ptr_cache_hit_is_returned_without_a_lookup() {
        let resolver = NetworkNameResolver::with_tables(synthetic_tables(), true, None);
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        resolver.cache_ptr(ip, Some("dns.google".to_owned()));
        let name = resolver.resolve(ip);
        assert_eq!(name.asn_org.as_deref(), Some("GOOGLE - Google LLC"));
        assert_eq!(name.ptr_hostname.as_deref(), Some("dns.google"));
        // A cached miss (PTR looked up, nothing there) is also
        // returned, not re-looked-up.
        let other: IpAddr = "1.0.0.1".parse().unwrap();
        resolver.cache_ptr(other, None);
        assert_eq!(resolver.resolve(other).ptr_hostname, None);
    }

    #[test]
    fn refresh_swap_replaces_the_table_and_a_bad_file_keeps_the_old_one() {
        // A "good" swap candidate must pass the sanity floor
        // (>100k ranges + 8.8.8.8 -> AS15169/GOOGLE), so generate
        // one: 100_005 consecutive /24s under 10/8 plus the
        // 8.8.8.0/24 GOOGLE row.
        let dir = std::env::temp_dir();
        let good_path = dir.join("bonded-test-asn-good.tsv");
        let bad_path = dir.join("bonded-test-asn-bad.tsv");
        let mut good = String::new();
        good.push_str("8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE - Google LLC\n");
        for i in 0..100_005u32 {
            let base = 0x0a00_0000u32 + i * 256;
            let start = std::net::Ipv4Addr::from(base);
            let end = std::net::Ipv4Addr::from(base + 255);
            good.push_str(&format!("{start}\t{end}\t64500\tUS\tTEST-ORG - Test Org\n"));
        }
        std::fs::write(&good_path, &good).expect("good file should be written");
        std::fs::write(&bad_path, "garbage, not a feed").expect("bad file should be written");

        let resolver = NetworkNameResolver::with_tables(synthetic_tables(), true, None);
        assert_eq!(resolver.range_count(), 3);
        // A good file swaps in: the new org appears and the range
        // count jumps.
        let report = resolver
            .swap_from_file(&good_path)
            .expect("good file should swap in");
        assert_eq!(report.old_range_count, 3);
        assert_eq!(report.new_range_count, 100_006);
        assert_eq!(resolver.range_count(), 100_006);
        assert_eq!(
            resolver.asn_org("10.0.5.5".parse().unwrap()).as_deref(),
            Some("TEST-ORG - Test Org")
        );
        assert_eq!(
            resolver.asn_org("8.8.8.8".parse().unwrap()).as_deref(),
            Some("GOOGLE - Google LLC")
        );
        // A bad file keeps the (new) old table untouched.
        assert!(resolver.swap_from_file(&bad_path).is_err());
        assert_eq!(resolver.range_count(), 100_006);
        assert_eq!(
            resolver.asn_org("10.0.5.5".parse().unwrap()).as_deref(),
            Some("TEST-ORG - Test Org")
        );
        // A too-small file (passes parsing, fails the sanity floor)
        // also keeps the old table.
        let small_path = dir.join("bonded-test-asn-small.tsv");
        std::fs::write(&small_path, synthetic_tsv()).expect("small file should be written");
        assert!(resolver.swap_from_file(&small_path).is_err());
        assert_eq!(resolver.range_count(), 100_006);
        let _ = std::fs::remove_file(good_path);
        let _ = std::fs::remove_file(bad_path);
        let _ = std::fs::remove_file(small_path);
    }

    /// Full refresh round-trip over a local HTTP server (not
    /// ignored): exercises the real download path — reqwest GET,
    /// temp file, parse + sanity verify, atomic rename, table
    /// swap — serving the synthetic 100k-range feed. The live
    /// feed over HTTPS is covered by `real_refresh_round_trip`
    /// (ignored): this sandbox MITMs TLS with its own CA, which
    /// rustls/webpki-roots correctly rejects, so a live-URL
    /// refresh cannot run here — it needs a non-MITM host
    /// (Anvil/Dell).
    #[tokio::test]
    async fn refresh_round_trip_over_local_http() {
        use bonded_core::config::ServerSection;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // Synthetic feed big enough to pass the sanity floor.
        let mut feed = String::new();
        feed.push_str("8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE - Google LLC\n");
        for i in 0..100_005u32 {
            let base = 0x0a00_0000u32 + i * 256;
            let start = std::net::Ipv4Addr::from(base);
            let end = std::net::Ipv4Addr::from(base + 255);
            feed.push_str(&format!(
                "{start}\t{end}\t64500\tUS\tTEST-ORG - Test Org\n"
            ));
        }
        let feed = feed.into_bytes();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener should bind");
        let addr = listener.local_addr().expect("listener should have an address");
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let feed = feed.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = socket.read(&mut buf).await;
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        feed.len()
                    );
                    let _ = socket.write_all(header.as_bytes()).await;
                    let _ = socket.write_all(&feed).await;
                });
            }
        });

        let dir = std::env::temp_dir().join("bonded-test-asn-refresh-http");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("ip2asn.tsv");
        let _ = std::fs::remove_file(&path);
        let mut cfg = ServerSection::default();
        cfg.asn_db_path = Some(path.to_string_lossy().into_owned());
        cfg.asn_db_auto_refresh = true;
        cfg.asn_db_url = Some(format!("http://{addr}/feed.tsv"));
        cfg.ptr_lookup = false;
        let resolver = NetworkNameResolver::from_config(&cfg);
        assert_eq!(resolver.range_count(), 0);

        let report = resolver
            .refresh()
            .await
            .expect("local refresh should succeed");
        assert_eq!(report.old_range_count, 0);
        assert_eq!(report.new_range_count, 100_006);
        assert!(path.exists());
        assert_eq!(
            resolver.asn_org("8.8.8.8".parse().unwrap()).as_deref(),
            Some("GOOGLE - Google LLC")
        );
        assert_eq!(
            resolver.asn_org("10.0.5.5".parse().unwrap()).as_deref(),
            Some("TEST-ORG - Test Org")
        );
        // A second refresh over the existing file succeeds and
        // keeps the same data.
        let report2 = resolver
            .refresh()
            .await
            .expect("second refresh should succeed");
        assert_eq!(report2.old_range_count, report.new_range_count);
        assert_eq!(report2.new_range_count, report.new_range_count);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    #[ignore]
    fn real_refresh_round_trip() {
        // Live refresh verification: downloads the real feed,
        // verifies it, writes it to the configured path, and swaps
        // the table in. Run with:
        //   cargo test -p bonded-server -- --ignored real_refresh_round_trip
        use bonded_core::config::ServerSection;
        let dir = std::env::temp_dir().join("bonded-test-asn-refresh");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("ip2asn.tsv.gz");
        let _ = std::fs::remove_file(&path);
        let mut cfg = ServerSection::default();
        cfg.asn_db_path = Some(path.to_string_lossy().into_owned());
        cfg.asn_db_auto_refresh = true;
        cfg.ptr_lookup = false;
        let resolver = NetworkNameResolver::from_config(&cfg);
        assert_eq!(resolver.range_count(), 0);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime should build");
        let report = rt
            .block_on(resolver.refresh())
            .expect("live refresh should succeed");
        assert!(report.new_range_count > 500_000);
        assert!(path.exists());
        assert_eq!(
            resolver.asn_org("8.8.8.8".parse().unwrap()).as_deref(),
            Some("GOOGLE - Google LLC")
        );
        // A second refresh over the existing file succeeds and
        // keeps the same data.
        let report2 = rt
            .block_on(resolver.refresh())
            .expect("second refresh should succeed");
        assert_eq!(report2.old_range_count, report.new_range_count);
        assert_eq!(report2.new_range_count, report.new_range_count);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    #[ignore]
    fn real_feed_spot_check() {
        // Live-feed verification against the real iptoasn.com
        // download (the file is ~11 MB; not fetched by unit tests).
        // Run with:
        //   BONDED_ASN_DB_TEST_PATH=/tmp/ip2asn.tsv.gz cargo test -p bonded-server -- --ignored real_feed_spot_check
        let path = std::env::var("BONDED_ASN_DB_TEST_PATH")
            .expect("BONDED_ASN_DB_TEST_PATH must point at a downloaded ip2asn-combined.tsv.gz");
        let tables =
            AsnTables::load_file(Path::new(&path)).expect("real feed should load");
        assert!(
            tables.range_count() > 500_000,
            "real feed should carry >500k routed ranges, got {}",
            tables.range_count()
        );
        tables.verify_sanity().expect("real feed should pass sanity");
        assert_eq!(
            tables.lookup("8.8.8.8".parse().unwrap()),
            Some("GOOGLE - Google LLC")
        );
        assert_eq!(
            tables.lookup("1.1.1.1".parse().unwrap()),
            Some("CLOUDFLARENET - Cloudflare, Inc.")
        );
        assert_eq!(tables.lookup("1.0.1.0".parse().unwrap()), None);
        assert_eq!(
            tables.lookup("2001:4860:4860::8888".parse().unwrap()),
            Some("GOOGLE - Google LLC")
        );
    }
}

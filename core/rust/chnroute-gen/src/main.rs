//! One-shot converter: read a MaxMind GeoLite2/GeoIP2 Country database and emit
//! a static `chnroute.txt` of merged IPv4 CIDRs for a chosen country (default
//! `CN`). This mirrors `shadowvpn::policy::geoip::load_country_routes` but is a
//! standalone host tool so the conversion is done once at build time and the
//! resulting plain-text CIDR list is bundled into the iOS app — no mmdb or
//! maxminddb dependency ships in the NetworkExtension.
//!
//! Usage: chnroute-gen <Country.mmdb> <out chnroute.txt> [COUNTRY=CN]

use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use ipnetwork::{IpNetwork, Ipv4Network};
use maxminddb::{geoip2, Reader, WithinOptions};

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let db = args.next().context("usage: chnroute-gen <mmdb> <out> [country]")?;
    let out = args.next().context("usage: chnroute-gen <mmdb> <out> [country]")?;
    let country = args.next().unwrap_or_else(|| "CN".to_string());

    let reader = Reader::open_readfile(&db).with_context(|| format!("opening {db}"))?;
    let all_v4 = IpNetwork::V4(Ipv4Network::new(Ipv4Addr::UNSPECIFIED, 0).unwrap());

    // Collect inclusive [start,end] ranges for the target country.
    let mut ranges: Vec<(u32, u32)> = Vec::new();
    for item in reader
        .within(all_v4, WithinOptions::default())
        .context("iterating GeoIP networks")?
    {
        let item = item.context("decoding network")?;
        let net = match item.network().context("reading network")? {
            IpNetwork::V4(v4) => v4,
            IpNetwork::V6(_) => continue,
        };
        let rec: Option<geoip2::Country> = item.decode().context("decoding country")?;
        let is_match = rec
            .and_then(|r| r.country.iso_code)
            .is_some_and(|iso| iso.eq_ignore_ascii_case(&country));
        if is_match {
            ranges.push((u32::from(net.network()), u32::from(net.broadcast())));
        }
    }

    // Sort + merge adjacent/overlapping ranges, then re-emit as minimal CIDRs.
    ranges.sort_unstable();
    let mut merged: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
    for (s, e) in ranges {
        if let Some(last) = merged.last_mut() {
            if s <= last.1.saturating_add(1) {
                if e > last.1 {
                    last.1 = e;
                }
                continue;
            }
        }
        merged.push((s, e));
    }

    let mut cidrs: Vec<String> = Vec::new();
    for (start, end) in &merged {
        range_to_cidrs(*start, *end, &mut cidrs);
    }

    let header = format!(
        "# chnroute ({country}) — generated once from a MaxMind GeoLite2 Country mmdb\n\
         # by core/rust/chnroute-gen. {} CIDR ranges.\n",
        cidrs.len()
    );
    std::fs::write(&out, format!("{header}{}\n", cidrs.join("\n")))
        .with_context(|| format!("writing {out}"))?;
    eprintln!("wrote {} CIDRs ({} merged ranges) -> {out}", cidrs.len(), merged.len());
    Ok(())
}

/// Decompose an inclusive [start,end] u32 range into the minimal set of CIDR
/// blocks (standard range-to-prefix splitting).
fn range_to_cidrs(mut start: u32, end: u32, out: &mut Vec<String>) {
    while start <= end {
        // Largest block whose alignment fits `start` and does not exceed `end`.
        let max_size_by_align = if start == 0 { 32 } else { start.trailing_zeros() };
        let max_size_by_span = 32 - ((end - start).saturating_add(1)).leading_zeros().min(32);
        let bits = max_size_by_align.min(if max_size_by_span == 0 { 0 } else { max_size_by_span - 1 });
        let prefix = 32 - bits;
        out.push(format!("{}/{}", Ipv4Addr::from(start), prefix));
        let block = 1u32.checked_shl(bits).unwrap_or(0);
        match start.checked_add(block) {
            Some(next) if block != 0 => start = next,
            _ => break, // covered up to u32::MAX
        }
    }
}

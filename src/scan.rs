//! Generic scanning helpers on top of the `Process` trait: byte-pattern
//! search, printable-string extraction, and region-driven full scans.
//!
//! The platform-specific memory access lives behind `Process` (`regions`,
//! `read_bytes_partial`); everything here is platform-independent and
//! byte-for-byte compatible with the diagnostic scans of the `reader`
//! crate it was extracted from (same match/resume progression, same
//! deduplication, same chunking).

use crate::{Process, RegionInfo};
use std::collections::HashSet;

/// A pattern hit inside a scanned chunk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanHit {
    /// Index of the matched pattern in the `patterns` slice.
    pub pattern_index: usize,
    /// Absolute address of the match.
    pub address: usize,
    /// Match offset within the scanned chunk.
    pub offset: usize,
}

/// Statistics of a `scan_regions` run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScanStats {
    /// Bytes actually read and scanned (readable prefix bytes only).
    pub walked: u64,
    /// Region chunks whose read produced zero bytes.
    pub failed_chunks: usize,
}

/// All offsets of `pattern` in `buffer`. The scan resumes after each match
/// (overlapping occurrences are not reported twice). Empty patterns
/// produce no hits.
pub fn find_pattern(buffer: &[u8], pattern: &[u8]) -> Vec<usize> {
    find_pattern_wildcard(buffer, pattern, None)
}

/// All offsets of `pattern` in `buffer`, ignoring bytes equal to `wildcard`
/// (e.g. the nibble mask byte of a disassembler signature); `None` disables
/// wildcards. The scan resumes after each match (overlapping occurrences
/// are not reported twice). Empty patterns produce no hits.
pub fn find_pattern_wildcard(
    buffer: &[u8],
    pattern: &[u8],
    wildcard: Option<u8>,
) -> Vec<usize> {
    let mut out = Vec::new();
    if pattern.is_empty() {
        return out;
    }

    let mut i = 0usize;
    while i + pattern.len() <= buffer.len() {
        if matches_at(buffer, i, pattern, wildcard) {
            out.push(i);
            i += pattern.len();
        } else {
            i += 1;
        }
    }
    out
}

fn matches_at(buffer: &[u8], i: usize, pattern: &[u8], wildcard: Option<u8>) -> bool {
    for (k, p) in pattern.iter().enumerate() {
        if Some(*p) != wildcard && buffer[i + k] != *p {
            return false;
        }
    }

    true
}

/// Printable ASCII/UTF-8 runs terminated by NUL or a non-printable byte;
/// must be valid UTF-8 and contain a non-ASCII char or a space (filters
/// binary junk); returns (offset-in-buf, string), capped at `max` results.
pub fn printable_runs(buf: &[u8], min_len: usize, max: usize) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < buf.len() && out.len() < max {
        let b = buf[i];
        if (0x20..0x7f).contains(&b) || b >= 0x80 {
            let mut n = 0usize;
            while i + n < buf.len() {
                let c = buf[i + n];
                if c == 0 || (0x20..0x7f).contains(&c) || c >= 0x80 {
                    if c == 0 {
                        break;
                    }
                    n += 1;
                } else {
                    break;
                }
            }
            if n >= min_len {
                if let Ok(s) = std::str::from_utf8(&buf[i..i + n]) {
                    let interesting = !s.is_ascii() || s.contains(' ');
                    if interesting && s.chars().count() >= min_len {
                        out.push((i, s.to_string()));
                    }
                }
                i += n + 1;
            } else {
                i += n.max(1) + 1;
            }
        } else {
            i += 1;
        }
    }
    out
}

/// Scan `regions` of `process` for fixed byte `patterns`.
///
/// Every region is read in `chunk_len`-byte chunks; a partially unreadable
/// chunk contributes only its readable prefix (chunks smaller than a
/// pattern produce no hits). Each unique absolute address — deduplicated
/// through `seen`, which the caller owns so dedup can persist across
/// calls — is reported once through `on_hit`; the chunk that produced the
/// hit is passed to the callback so context (hex dumps, containing
/// C-strings) can be extracted from it. Returning `false` from `on_hit`
/// aborts the scan immediately (hit caps). `on_progress` is called after
/// each region with the region end address and the number of bytes walked
/// so far.
///
/// Region filtering (committed, non-image, minimum size, ...) is the
/// caller's responsibility: pass the regions returned by
/// `Process::regions` after filtering. Note that patterns straddling a
/// chunk boundary are not found — the same limitation the original
/// reader-side scanner had.
pub fn scan_regions<P: Process>(
    process: &P,
    regions: &[RegionInfo],
    patterns: &[Vec<u8>],
    seen: &mut HashSet<usize>,
    chunk_len: usize,
    mut on_hit: impl FnMut(&ScanHit, &[u8]) -> bool,
    mut on_progress: impl FnMut(usize, u64),
) -> ScanStats {
    let mut stats = ScanStats::default();
    let mut chunk = vec![0u8; chunk_len.max(1)];

    for region in regions {
        let end = region.base.saturating_add(region.size);
        let mut a = region.base;

        while a < end {
            let want = chunk.len().min(end - a);
            let got = process.read_bytes_partial(a, &mut chunk[..want]);

            if got > 0 {
                let window = &chunk[..got];

                for (pi, pat) in patterns.iter().enumerate() {
                    for off in find_pattern(window, pat) {
                        let hit = ScanHit {
                            pattern_index: pi,
                            address: a + off,
                            offset: off,
                        };

                        if seen.insert(hit.address) && !on_hit(&hit, window) {
                            return stats;
                        }
                    }
                }

                stats.walked += got as u64;
            } else {
                stats.failed_chunks += 1;
            }

            a += want.max(0x1000);
        }

        on_progress(end, stats.walked);
    }

    stats
}


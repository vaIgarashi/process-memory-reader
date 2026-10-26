//! Unit tests for the generic scanning helpers (page-granular mock process).

use process_memory_reader::scan::{
    find_pattern, find_pattern_wildcard, printable_runs, scan_regions,
};
use process_memory_reader::{MemoryReadError, Process, RegionInfo, RegionKind};
use std::collections::{HashMap, HashSet};

/// In-memory process mock: `pages` maps page base -> page bytes; regions
/// are reported exactly as added (unbacked regions read as zero bytes).
struct MockProcess {
    pages: HashMap<usize, Vec<u8>>,
    regions: Vec<RegionInfo>,
}

impl MockProcess {
    fn new() -> Self {
        MockProcess {
            pages: HashMap::new(),
            regions: Vec::new(),
        }
    }

    fn add_region(
        &mut self,
        base: usize,
        size: usize,
        kind: RegionKind,
        fill: impl Fn(usize) -> u8,
    ) {
        for start in (0..size).step_by(0x1000) {
            let stop = size.min(start + 0x1000);
            let data: Vec<u8> = (start..stop).map(|k| fill(base + k)).collect();
            self.pages.insert(base + start, data);
        }
        self.regions.push(RegionInfo { base, size, kind });
    }

    fn add_unbacked_region(&mut self, base: usize, size: usize) {
        self.regions.push(RegionInfo {
            base,
            size,
            kind: RegionKind::Private,
        });
    }
}

impl Process for MockProcess {
    fn base_address(&self, _module: &str) -> Option<usize> {
        None
    }

    fn regions(&self) -> Vec<RegionInfo> {
        self.regions.clone()
    }

    fn read_bytes_partial(&self, address: usize, buffer: &mut [u8]) -> usize {
        let mut read = 0usize;
        while read < buffer.len() {
            let addr = address + read;
            let page = addr & !0xFFF;
            let off = addr & 0xFFF;
            match self.pages.get(&page) {
                Some(bytes) => {
                    if off >= bytes.len() {
                        break;
                    }
                    let n = (0x1000 - off).min(buffer.len() - read).min(bytes.len() - off);
                    buffer[read..read + n].copy_from_slice(&bytes[off..off + n]);
                    read += n;
                }
                None => break,
            }
        }
        read
    }

    fn read_bytes(&self, address: usize, buffer: &mut [u8]) -> Result<(), MemoryReadError> {
        let read = self.read_bytes_partial(address, buffer);
        if read == buffer.len() {
            Ok(())
        } else {
            Err(MemoryReadError::InaccessibleMemoryAddress { address })
        }
    }
}

#[test]
fn find_pattern_finds_all_matches_resuming_after_each() {
    let buf = [0xAA, 0xBB, 0xAA, 0xBB, 0xAA, 0xBB, 0xAA];
    assert_eq!(find_pattern(&buf, &[0xAA, 0xBB]), vec![0, 2, 4]);
}

#[test]
fn find_pattern_overlapping_matches_collapse() {
    // reader parity: on a match the scan resumes after it, so AAAAA with a
    // 4-byte pattern yields only offset 0.
    let buf = [1u8, 1, 1, 1, 1];
    assert_eq!(find_pattern(&buf, &[1, 1, 1, 1]), vec![0]);
}

#[test]
fn find_pattern_empty_pattern_yields_nothing() {
    let buf = [1u8, 2, 3];
    assert!(find_pattern(&buf, &[]).is_empty());
}

#[test]
fn find_pattern_wildcard_ignores_masked_bytes() {
    let buf = [1u8, 0x42, 2, 1, 0x99, 2];
    assert_eq!(
        find_pattern_wildcard(&buf, &[1, 0x3F, 2], Some(0x3F)),
        vec![0, 3]
    );
}

#[test]
fn printable_runs_filters_binary_junk() {
    let mut buf = vec![0u8; 16];
    buf.extend_from_slice("hello world\0".as_bytes()); // space -> kept
    buf.extend_from_slice("abcdef\0".as_bytes()); // ascii-only, no space -> filtered
    buf.extend_from_slice("привет мир\0".as_bytes()); // non-ascii -> kept

    let runs = printable_runs(&buf, 4, 10);
    let strs: Vec<&str> = runs.iter().map(|r| r.1.as_str()).collect();
    assert_eq!(strs, vec!["hello world", "привет мир"]);
}

#[test]
fn scan_regions_reports_deduped_hits_across_chunks() {
    let mut mock = MockProcess::new();
    mock.add_region(0x100_000, 0x3000, RegionKind::Private, |addr| {
        if addr == 0x100_008 || addr == 0x100_018 {
            0x77
        } else {
            0
        }
    });

    let patterns = vec![vec![0x77u8, 0, 0, 0, 0, 0, 0, 0]];
    let mut seen = HashSet::new();
    let mut hits: Vec<usize> = Vec::new();

    let stats = scan_regions(
        &mock,
        &mock.regions,
        &patterns,
        &mut seen,
        0x1000, // chunk smaller than the region -> chunking exercised
        |hit, _chunk| {
            hits.push(hit.address);
            true
        },
        |_, _| {},
    );

    assert_eq!(hits, vec![0x100_008, 0x100_018]);
    assert_eq!(stats.walked, 0x3000);
    assert_eq!(stats.failed_chunks, 0);
}

#[test]
fn scan_regions_stops_on_hit_cap() {
    let mut mock = MockProcess::new();
    mock.add_region(0x100_000, 0x2000, RegionKind::Private, |addr| {
        if addr == 0x100_010 {
            0x99
        } else {
            0
        }
    });
    mock.add_region(0x200_000, 0x2000, RegionKind::Private, |addr| {
        if addr == 0x200_010 {
            0x99
        } else {
            0
        }
    });

    let patterns = vec![vec![0x99u8, 0, 0, 0, 0, 0, 0, 0]];
    let mut seen = HashSet::new();
    let mut hits: Vec<usize> = Vec::new();

    let stats = scan_regions(
        &mock,
        &mock.regions,
        &patterns,
        &mut seen,
        0x20_0000,
        |hit, _chunk| {
            hits.push(hit.address);
            false // cap reached
        },
        |_, _| {},
    );

    assert_eq!(hits, vec![0x100_010]); // second region never reached
    assert_eq!(stats.walked, 0); // aborted before the first chunk counted
}

#[test]
fn scan_regions_skips_unreadable_and_counts_failures() {
    let mut mock = MockProcess::new();
    mock.add_unbacked_region(0x300_000, 0x1000);
    mock.add_region(0x400_000, 0x1000, RegionKind::Private, |addr| {
        if addr == 0x400_010 {
            0xAB
        } else {
            0
        }
    });

    let patterns = vec![vec![0xABu8]];
    let mut seen = HashSet::new();
    let mut hits: Vec<usize> = Vec::new();
    let mut progress: Vec<(usize, u64)> = Vec::new();

    let stats = scan_regions(
        &mock,
        &mock.regions,
        &patterns,
        &mut seen,
        0x20_0000,
        |hit, _chunk| {
            hits.push(hit.address);
            true
        },
        |end, walked| progress.push((end, walked)),
    );

    assert_eq!(hits, vec![0x400_010]);
    assert_eq!(stats.failed_chunks, 1);
    assert_eq!(stats.walked, 0x1000);
    assert_eq!(progress, vec![(0x301_000, 0), (0x401_000, 0x1000)]);
}

#[test]
fn scan_regions_dedup_persists_across_calls_via_shared_seen() {
    let mut mock = MockProcess::new();
    mock.add_region(0x100_000, 0x1000, RegionKind::Private, |addr| {
        if addr == 0x100_010 {
            0x42
        } else {
            0
        }
    });

    let patterns = vec![vec![0x42u8]];
    let mut seen = HashSet::new();
    let mut calls = 0usize;

    for _ in 0..2 {
        scan_regions(
            &mock,
            &mock.regions,
            &patterns,
            &mut seen,
            0x20_0000,
            |_hit, _chunk| {
                calls += 1;
                true
            },
            |_, _| {},
        );
    }

    assert_eq!(calls, 1); // second call sees the same hit only through `seen`
}


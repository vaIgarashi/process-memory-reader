//! Enumerate committed regions of a target process and smoke-check
//! `read_bytes_partial`. Usage: `cargo run --example regions -- <pid>`

use process_memory_reader::{Process, RegionKind};

fn main() {
    let pid = std::env::args().nth(1).unwrap().parse::<u32>().unwrap();
    let process = process_memory_reader::open_process(pid).unwrap();

    let regions = process.regions();
    let total: usize = regions.iter().map(|r| r.size).sum();

    println!("regions={} total_bytes={}", regions.len(), total);

    for kind in [RegionKind::Private, RegionKind::Mapped, RegionKind::Image] {
        let size: usize = regions
            .iter()
            .filter(|r| r.kind == kind)
            .map(|r| r.size)
            .sum();

        println!("  {:?}: {} regions, {} bytes", kind, regions.iter().filter(|r| r.kind == kind).count(), size);
    }

    for region in regions.iter().take(5) {
        println!("  {:016x} {:?} {} bytes", region.base, region.kind, region.size);
    }

    // Partial read smoke checks.
    let mut buf = [0u8; 64];
    let n = process.read_bytes_partial(regions[0].base, &mut buf);
    println!("partial at image base: {}/64 bytes", n);

    let n = process.read_bytes_partial(0x10000, &mut buf);
    println!("partial at 0x10000 (likely free): {}/64 bytes", n);
}

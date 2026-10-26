# process-memory-reader
[![crates.io](https://img.shields.io/crates/v/process-memory-reader.svg)](https://crates.io/crates/process-memory-reader)

Crate for reading process memory

## Example
```rust,no_run
use process_memory_reader::{open_process, Process};

let process = process_memory_reader::open_process(22212).unwrap();
let base_address = process.base_address("Notepad.exe").unwrap();

process.read_u8(base_address + 0x127).unwrap();
```

## Regions

Enumerate the committed regions of the target address space:

```rust,no_run
use process_memory_reader::{open_process, Process};

let process = open_process(666).unwrap();

for region in process.regions() {
    println!("{:016x} {:?} {} bytes", region.base, region.kind, region.size);
}
```

## Partial reads

`read_bytes_partial` returns the readable contiguous prefix of the buffer:

```rust,no_run
use process_memory_reader::{open_process, Process};
let process = open_process(666).unwrap();

let mut buffer = [0u8; 4096];
let read = process.read_bytes_partial(0x00, &mut buffer);
println!("read {} of {} bytes", read, buffer.len());
```

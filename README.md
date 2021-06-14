# process-memory-reader
[![crates.io](https://img.shields.io/crates/v/process-memory-reader.svg)](https://crates.io/crates/process-memory-reader)

Crate for reading process memory

## Example
```rust
use process_memory_reader::Process;

let process = process_memory_reader::open_process(22212).unwrap();
let base_address = process.base_address("Notepad.exe").unwrap();

process.read_u8(base_address + 0x127).unwrap();
```
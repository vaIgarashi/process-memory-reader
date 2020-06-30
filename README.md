# process-memory-reader

API to read process memory using WinAPI.

## Example
```rust
use process_memory_reader::Process;

let process = Process::open_process(22212).unwrap();
let base_address = process.base_address("Notepad.exe").unwrap();

process.read_u8(base_address + 0x127).unwrap();
```
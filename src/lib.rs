//! Crate for reading process memory.
//!
//! # Example
//! ```no_run
//! use process_memory_reader::Process;
//!
//! let process = process_memory_reader::open_process(22212).unwrap();
//! let base_address = process.base_address("Notepad.exe").unwrap();
//!
//! process.read_u8(base_address + 0x127).unwrap();
//! ```

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub use windows::*;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

pub mod scan;

/// The kind of backing store of a committed memory region.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RegionKind {
    /// Anonymous private memory (heaps, stacks).
    Private,
    /// File-backed data mapping (`MEM_MAPPED` on Windows, a mapped regular
    /// file on Linux).
    Mapped,
    /// Executable image mapping (`MEM_IMAGE` on Windows, the main
    /// executable or a shared object on Linux).
    Image,
}

/// One committed region of the target process address space.
///
/// Windows: one `VirtualQueryEx` entry with `State == MEM_COMMIT`;
/// Linux: one `/proc/<pid>/maps` entry. Free and reserved address space is
/// not reported; the null page is skipped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegionInfo {
    /// Region base address (page-aligned).
    pub base: usize,
    /// Region size in bytes (a multiple of the page size).
    pub size: usize,
    /// Backing-store kind.
    pub kind: RegionKind,
}

use std::io::Error as IoError;

/// Errors that can be caught when trying to read process memory.
#[derive(Debug)]
pub enum MemoryReadError {
    InaccessibleMemoryAddress { address: usize },
    LessBytesRead { expected: usize, actual: usize },
    IOError { io_error: IoError },
}

impl From<IoError> for MemoryReadError {
    fn from(io_error: IoError) -> Self {
        MemoryReadError::IOError { io_error }
    }
}

macro_rules! define_number_read (
    ($type: ident, $name: ident, $bytes: expr) => (
        fn $name(&self, address: usize) -> Result<$type, MemoryReadError> {
            let mut buffer = [0u8; $bytes];
            self.read_bytes(address, &mut buffer)?;

            Ok($type::from_le_bytes(buffer))
        }
   );
);

pub trait Process {
    /// Finds process module base address.
    fn base_address(&self, module_name: &str) -> Option<usize>;

    /// Read the specified length in bytes from the address memory.
    fn read_bytes(&self, address: usize, buffer: &mut [u8]) -> Result<(), MemoryReadError>;

    /// Enumerate the committed regions of the process address space, in
    /// ascending base order (never overlapping, page-aligned bases).
    fn regions(&self) -> Vec<RegionInfo>;

    /// Read the readable contiguous prefix of `buffer` starting at
    /// `address`; returns how many bytes were actually read,
    /// `0..=buffer.len()`. Unlike `read_bytes`, a partially unreadable span
    /// is not an error: the caller keeps the readable prefix (`0` means
    /// nothing at `address` was readable).
    fn read_bytes_partial(&self, address: usize, buffer: &mut [u8]) -> usize;

    /// Read string until null char are read.
    fn read_string(&self, address: usize) -> Result<String, MemoryReadError> {
        let mut buffer = Vec::new();
        let mut index = 0;

        loop {
            let ch = self.read_u8(address + index)?;

            if ch == 0 {
                break;
            }

            buffer.insert(index, ch);
            index += 1;
        }

        Ok(String::from_utf8(buffer).unwrap_or(String::from("")))
    }

    fn read_u8(&self, address: usize) -> Result<u8, MemoryReadError> {
        let mut buffer = [0u8; 1];
        self.read_bytes(address, &mut buffer)?;

        Ok(buffer[0])
    }

    fn read_bool(&self, address: usize) -> Result<bool, MemoryReadError> {
        Ok(self.read_u8(address)? == 1)
    }

    define_number_read!(u32, read_u32, 4);
    define_number_read!(u64, read_u64, 8);
    define_number_read!(u128, read_u128, 16);
    define_number_read!(i32, read_i32, 4);
    define_number_read!(i64, read_i64, 8);
    define_number_read!(f32, read_f32, 4);
    define_number_read!(f64, read_f64, 8);
}

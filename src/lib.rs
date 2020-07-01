//! API to read process memory using WinAPI.
//!
//! # Example
//! ```no_run
//! use process_memory_reader::Process;
//!
//! let process = Process::open_process(22212).unwrap();
//! let base_address = process.base_address("Notepad.exe").unwrap();
//!
//! process.read_u8(base_address + 0x127).unwrap();
//! ```
use std::ffi::OsString;
use std::mem::{size_of, size_of_val, MaybeUninit};
use std::os::windows::ffi::OsStringExt;
use std::ptr;
use winapi::ctypes::c_void;
use winapi::shared::minwindef::{DWORD, HMODULE, MAX_PATH, TRUE};
use winapi::um::handleapi::CloseHandle;
use winapi::um::memoryapi::ReadProcessMemory;
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::psapi::{EnumProcessModules, GetModuleBaseNameA};
use winapi::um::tlhelp32::PROCESSENTRY32W;
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use winapi::um::winnt::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

/// Errors that can be caught when trying to read process memory.
#[derive(Debug)]
pub enum MemoryReadError {
    InaccessibleMemoryAddress { address: u64 },
    LessBytesRead { expected: u64, actual: u64 },
}

#[derive(Debug)]
pub struct Process {
    handle: *mut c_void,
}

macro_rules! define_number_read (
    ($type: ident, $name: ident, $bytes: expr) => (
        pub fn $name(&self, address: u64) -> Result<$type, MemoryReadError> {
            let mut buffer = [0u8; $bytes];
            self.read_bytes(address, &mut buffer)?;

            Ok($type::from_le_bytes(buffer))
        }
   );
);

impl Process {
    /// Opens process with specified id.
    ///
    /// If the process is not found or could not be opened `None` will be returned.
    pub fn open_process(pid: u32) -> Option<Process> {
        let handle = unsafe { OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid) };

        if handle.is_null() {
            return None;
        }

        Some(Process { handle })
    }

    /// Finds all processes with matching name.
    pub fn find_by_name(name: &str) -> Vec<Process> {
        let handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        let mut processes = Vec::new();

        if handle.is_null() {
            return processes;
        }

        let mut maybe_entry = MaybeUninit::<PROCESSENTRY32W>::uninit();

        unsafe {
            ptr::write(
                &mut (*maybe_entry.as_mut_ptr()).dwSize,
                size_of::<PROCESSENTRY32W>() as u32,
            );
        }

        if unsafe { Process32FirstW(handle, maybe_entry.as_mut_ptr()) } == TRUE {
            while unsafe { Process32NextW(handle, maybe_entry.as_mut_ptr()) } == TRUE {
                let entry = unsafe { maybe_entry.assume_init() };

                let process_name_full = &entry.szExeFile;
                let process_name_length = process_name_full.iter().take_while(|&&c| c != 0).count();
                let process_name = &OsString::from_wide(&process_name_full[..process_name_length]);

                if process_name != name {
                    continue;
                }

                Process::open_process(entry.th32ProcessID).map(|process| processes.push(process));
            }
        }

        unsafe {
            CloseHandle(handle);
        }

        processes
    }

    /// Finds process module base address.
    pub fn base_address(&self, module_name: &str) -> Option<u64> {
        let mut maybe_hmod = MaybeUninit::<HMODULE>::uninit();
        let mut maybe_cb_needed = MaybeUninit::<DWORD>::uninit();

        let result = unsafe {
            EnumProcessModules(
                self.handle,
                maybe_hmod.as_mut_ptr(),
                size_of_val(&maybe_hmod) as u32,
                maybe_cb_needed.as_mut_ptr(),
            )
        };

        if result != TRUE {
            return None;
        }

        let mut base_name_vec: Vec<u8> = Vec::with_capacity(MAX_PATH);

        unsafe {
            let base_name_length = GetModuleBaseNameA(
                self.handle,
                maybe_hmod.assume_init(),
                base_name_vec.as_mut_ptr() as *mut _,
                base_name_vec.capacity() as u32,
            );

            base_name_vec.set_len(base_name_length as usize)
        }

        let base_name = String::from_utf8_lossy(&base_name_vec);

        if base_name.to_lowercase() == module_name.to_lowercase() {
            unsafe { Some(maybe_hmod.assume_init() as u64) }
        } else {
            None
        }
    }

    /// Read the specified length in bytes from the address memory.
    pub fn read_bytes(&self, address: u64, buffer: &mut [u8]) -> Result<(), MemoryReadError> {
        let mut maybe_read = MaybeUninit::<usize>::uninit();

        let result = unsafe {
            ReadProcessMemory(
                self.handle,
                address as *const _,
                buffer.as_mut_ptr() as *mut _,
                buffer.len(),
                maybe_read.as_mut_ptr(),
            )
        };

        if result != TRUE {
            return Err(MemoryReadError::InaccessibleMemoryAddress { address });
        }

        let read = unsafe { maybe_read.assume_init() as u64 };

        if read != buffer.len() as u64 {
            return Err(MemoryReadError::LessBytesRead {
                expected: buffer.len() as u64,
                actual: read,
            });
        }

        Ok(())
    }

    /// Read string until null char are read.
    pub fn read_string(&self, address: u64) -> Result<String, MemoryReadError> {
        let mut buffer = Vec::new();
        let mut index = 0;

        loop {
            let ch = self.read_u8(address + index as u64)?;

            if ch == 0 {
                break;
            }

            buffer.insert(index, ch);
            index += 1;
        }

        Ok(String::from_utf8(buffer).unwrap_or(String::from("")))
    }

    pub fn read_u8(&self, address: u64) -> Result<u8, MemoryReadError> {
        let mut buffer = [0u8; 1];
        self.read_bytes(address, &mut buffer)?;

        Ok(buffer[0])
    }

    pub fn read_bool(&self, address: u64) -> Result<bool, MemoryReadError> {
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

impl Drop for Process {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}
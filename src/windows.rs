use crate::{MemoryReadError, Process, RegionInfo, RegionKind};
use std::ffi::OsString;
use std::mem::{size_of, size_of_val, zeroed, MaybeUninit};
use std::os::windows::ffi::OsStringExt;
use std::ptr;
use winapi::ctypes::c_void;
use winapi::shared::minwindef::{DWORD, HMODULE, MAX_PATH, TRUE};
use winapi::um::handleapi::CloseHandle;
use winapi::um::memoryapi::{ReadProcessMemory, VirtualQueryEx};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::psapi::{EnumProcessModules, GetModuleBaseNameA};
use winapi::um::tlhelp32::PROCESSENTRY32W;
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use winapi::um::winnt::{
    MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_PRIVATE, PROCESS_QUERY_INFORMATION,
    PROCESS_VM_READ,
};

/// Opens process with specified id.
///
/// If the process is not found or could not be opened `None` will be returned.
pub fn open_process(pid: u32) -> Option<WindowsProcess> {
    let handle = unsafe { OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid) };

    if handle.is_null() {
        return None;
    }

    Some(WindowsProcess { pid, handle })
}

/// Finds all processes with matching name.
pub fn find_by_name(name: &str) -> Vec<WindowsProcess> {
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

            if let Some(process) = open_process(entry.th32ProcessID) { processes.push(process) }
        }
    }

    unsafe {
        CloseHandle(handle);
    }

    processes
}

#[derive(Debug)]
pub struct WindowsProcess {
    pid: u32,
    handle: *mut c_void,
}

// SAFETY: the handle is a kernel object id, not tied to any thread, and the
// WinAPI calls used with it (ReadProcessMemory, module enumeration) are
// thread-safe; there is no other interior state. Send is what lets consumers
// move the process to a dedicated reader thread; Sync additionally allows
// shared reads, since every method takes &self and only performs syscalls.
// Drop closes the handle exactly once, as with any owned value.
unsafe impl Send for WindowsProcess {}
unsafe impl Sync for WindowsProcess {}

/// One `ReadProcessMemory` call: `Some(bytes read)` on success, `None` on
/// failure. An empty buffer is trivially `Some(0)` without a syscall.
fn read_once(handle: *mut c_void, address: usize, buffer: &mut [u8]) -> Option<usize> {
    if buffer.is_empty() {
        return Some(0);
    }

    let mut maybe_read = MaybeUninit::<usize>::uninit();

    let result = unsafe {
        ReadProcessMemory(
            handle,
            address as *const _,
            buffer.as_mut_ptr() as *mut _,
            buffer.len(),
            maybe_read.as_mut_ptr(),
        )
    };

    if result != TRUE {
        return None;
    }

    Some(unsafe { maybe_read.assume_init() })
}

/// Top of the user-mode address space walked by `regions()`: the kernel
/// shadow area starts at `0x7FFF_FFFF_FFFF` on 64-bit; just below 4 GiB on
/// 32-bit.
fn user_address_space_limit() -> usize {
    if usize::BITS >= 48 {
        0x7FFF_FFFF_FFFFusize
    } else {
        0xFFFF_0000usize
    }
}

fn region_kind(region_type: DWORD) -> RegionKind {
    if region_type == MEM_PRIVATE {
        RegionKind::Private
    } else if region_type == MEM_IMAGE {
        RegionKind::Image
    } else {
        // MEM_MAPPED and any combined flags
        RegionKind::Mapped
    }
}

impl Process for WindowsProcess {
    fn base_address(&self, module_name: &str) -> Option<usize> {
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
            unsafe { Some(maybe_hmod.assume_init() as usize) }
        } else {
            None
        }
    }

    fn read_bytes(&self, address: usize, buffer: &mut [u8]) -> Result<(), MemoryReadError> {
        match read_once(self.handle, address, buffer) {
            Some(read) if read == buffer.len() => Ok(()),
            Some(read) => Err(MemoryReadError::LessBytesRead {
                expected: buffer.len(),
                actual: read,
            }),
            None => Err(MemoryReadError::InaccessibleMemoryAddress { address }),
        }
    }

    fn regions(&self) -> Vec<RegionInfo> {
        let mut regions = Vec::new();
        let mut address = 0usize;
        let limit = user_address_space_limit();

        while address < limit {
            let mut info: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };

            if unsafe {
                VirtualQueryEx(
                    self.handle,
                    address as *const _,
                    &mut info,
                    size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            } == 0
            {
                break;
            }

            let region_base = info.BaseAddress as usize;
            let region_size = info.RegionSize as usize;
            let next = region_base + region_size;

            if info.State == MEM_COMMIT && region_size > 0 && region_base != 0 {
                regions.push(RegionInfo {
                    base: region_base,
                    size: region_size,
                    kind: region_kind(info.Type),
                });
            }

            address = next.max(address + 0x1000);
        }

        regions
    }

    fn read_bytes_partial(&self, address: usize, buffer: &mut [u8]) -> usize {
        if buffer.is_empty() {
            return 0;
        }

        let mut read = match read_once(self.handle, address, buffer) {
            Some(read) => read,
            None => return 0,
        };

        if read == 0 {
            return 0;
        }

        while read < buffer.len() {
            let chunk = match read_once(self.handle, address + read, &mut buffer[read..]) {
                Some(chunk) if chunk > 0 => chunk,
                _ => break,
            };

            read += chunk;
        }

        read
    }
}

impl Drop for WindowsProcess {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}


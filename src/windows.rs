use crate::{MemoryReadError, Process};
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

            open_process(entry.th32ProcessID).map(|process| processes.push(process));
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

        let read = unsafe { maybe_read.assume_init() };

        if read != buffer.len() {
            return Err(MemoryReadError::LessBytesRead {
                expected: buffer.len(),
                actual: read,
            });
        }

        Ok(())
    }
}

impl Drop for WindowsProcess {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

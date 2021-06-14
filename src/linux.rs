use crate::{MemoryReadError, Process};
use libc::{iovec, process_vm_readv};
use std::fs::{read_dir, File};
use std::io::{Error as IoError, BufReader, BufRead};

/// Opens process with specified id.
///
/// If the process is not found or could not be opened `None` will be returned.
pub fn open_process(pid: u32) -> Option<LinuxProcess> {
    Some(LinuxProcess { pid })
}

/// Finds all processes with matching name.
pub fn find_by_name(name: &str) -> Result<Vec<LinuxProcess>, IoError> {
    let paths = read_dir("/proc")?;
    let mut processes = vec![];

    for path_entry in paths {
        if let Ok(path) = path_entry {
            let maps_path = path.path().join("maps");

            if let Ok(file) = File::open(maps_path) {
                let mut reader = BufReader::new(file);
                let mut buffer = String::new();
                reader.read_line(&mut buffer)?;

                if buffer.trim().ends_with(name) {
                    if let Some(pid_name) = path.file_name().to_str() {
                        let pid = pid_name.parse::<u32>().unwrap();

                        open_process(pid).map(|process| processes.push(process));
                    }
                }
            }
        }
    }

    Ok(processes)
}

#[derive(Debug)]
pub struct LinuxProcess {
    pub pid: u32,
}

impl Process for LinuxProcess {
    fn base_address(&self, module_name: &str) -> Option<usize> {
        let file_name = format!("/proc/{}/maps", self.pid);
        let file = File::open(file_name).ok()?;
        let reader = BufReader::new(file);

        for result in reader.lines() {
            if let Ok(line) = result {
                if line.trim().ends_with(module_name) {
                    let split_line: Vec<&str> = line.split("-").collect();
                    let address_str = split_line[0];

                    return usize::from_str_radix(address_str, 16).ok();
                }
            }
        }

        None
    }

    fn read_bytes(&self, address: usize, buffer: &mut [u8]) -> Result<(), MemoryReadError> {
        let local_iov = iovec {
            iov_base: buffer.as_mut_ptr() as *mut _,
            iov_len: buffer.len(),
        };

        let remote_iov = iovec {
            iov_base: address as *mut _,
            iov_len: buffer.len(),
        };

        let result = unsafe { process_vm_readv(self.pid as i32, &local_iov, 1, &remote_iov, 1, 0) };

        if result == -1 {
            return Err(MemoryReadError::IOError {
                io_error: IoError::last_os_error(),
            });
        }

        let read = result as usize;

        if read != buffer.len() {
            return Err(MemoryReadError::LessBytesRead {
                expected: buffer.len(),
                actual: read,
            });
        }

        Ok(())
    }
}

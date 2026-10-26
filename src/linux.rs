use crate::{MemoryReadError, Process, RegionInfo, RegionKind};
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

/// One `process_vm_readv` call: `Some(bytes read)` on success, `None` on
/// failure (including partial failures of a multi-iovec transfer). An empty
/// buffer is trivially `Some(0)` without a syscall.
fn read_remote(pid: u32, address: usize, buffer: &mut [u8]) -> Option<usize> {
    if buffer.is_empty() {
        return Some(0);
    }

    let local_iov = iovec {
        iov_base: buffer.as_mut_ptr() as *mut _,
        iov_len: buffer.len(),
    };

    let remote_iov = iovec {
        iov_base: address as *mut _,
        iov_len: buffer.len(),
    };

    let result = unsafe { process_vm_readv(pid as i32, &local_iov, 1, &remote_iov, 1, 0) };

    if result == -1 {
        return None;
    }

    Some(result as usize)
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
        let read =
            read_remote(self.pid, address, buffer).ok_or_else(|| IoError::last_os_error())?;

        if read != buffer.len() {
            return Err(MemoryReadError::LessBytesRead {
                expected: buffer.len(),
                actual: read,
            });
        }

        Ok(())
    }

    fn regions(&self) -> Vec<RegionInfo> {
        let maps_path = format!("/proc/{}/maps", self.pid);
        let file = match File::open(maps_path) {
            Ok(file) => file,
            Err(_) => return Vec::new(),
        };

        let reader = BufReader::new(file);
        let mut regions = Vec::new();

        for result in reader.lines() {
            let line = match result {
                Ok(line) => line,
                Err(_) => break,
            };

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let mut fields = trimmed.split_whitespace();
            let range = match fields.next() {
                Some(range) => range,
                None => continue,
            };

            let mut range_parts = range.split('-');
            let start = match range_parts.next().and_then(|s| usize::from_str_radix(s, 16).ok()) {
                Some(start) => start,
                None => continue,
            };
            let end = match range_parts.next().and_then(|s| usize::from_str_radix(s, 16).ok()) {
                Some(end) => end,
                None => continue,
            };

            if end <= start {
                continue;
            }

            let perms = fields.next().unwrap_or("");
            let pathname = fields.next_back().unwrap_or("");

            let kind = if pathname.is_empty() || pathname.starts_with('[') {
                RegionKind::Private
            } else if perms.contains('x') {
                RegionKind::Image
            } else if pathname.starts_with('/') {
                RegionKind::Mapped
            } else {
                RegionKind::Image
            };

            if start == 0 {
                continue;
            }

            regions.push(RegionInfo {
                base: start,
                size: end - start,
                kind,
            });
        }

        regions
    }

    fn read_bytes_partial(&self, address: usize, buffer: &mut [u8]) -> usize {
        if buffer.is_empty() {
            return 0;
        }

        let mut read = match read_remote(self.pid, address, buffer) {
            Some(read) => read,
            None => return 0,
        };

        if read == 0 {
            return 0;
        }

        while read < buffer.len() {
            let chunk = match read_remote(self.pid, address + read, &mut buffer[read..]) {
                Some(chunk) if chunk > 0 => chunk,
                _ => break,
            };

            read += chunk;
        }

        read
    }
}

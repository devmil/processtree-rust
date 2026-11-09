//! Documented Windows Process Snapshotting API for open-file metadata. The
//! helper executes this in a finite child because filesystem name resolution
//! can wait inside drivers. No address-space clone or file contents are read.
use super::{CapabilityState, FileDescriptorInfo, FileDescriptorResult};
use std::{io, mem::size_of, ptr};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::{Diagnostics::ProcessSnapshotting::*, Threading::*};
struct Owned(HANDLE);
impl Drop for Owned {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
struct Snapshot(HPSS);
impl Drop for Snapshot {
    fn drop(&mut self) {
        unsafe {
            PssFreeSnapshot(GetCurrentProcess(), self.0);
        }
    }
}
struct Marker(HPSSWALK);
impl Drop for Marker {
    fn drop(&mut self) {
        unsafe {
            PssWalkMarkerFree(self.0);
        }
    }
}
fn check(code: u32) -> io::Result<()> {
    if code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}
pub(super) fn query(pid: i32) -> FileDescriptorResult {
    match query_inner(pid) {
        Ok(descriptors) => FileDescriptorResult {
            state: CapabilityState::Available,
            descriptors,
        },
        Err(_) => FileDescriptorResult {
            state: CapabilityState::Restricted {
                reason: "process file handles unavailable".into(),
            },
            descriptors: vec![],
        },
    }
}
fn query_inner(pid: i32) -> io::Result<Vec<FileDescriptorInfo>> {
    if pid <= 0 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let process = unsafe {
        OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE,
            0,
            pid as u32,
        )
    };
    if process.is_null() {
        return Err(io::Error::last_os_error());
    }
    let process = Owned(process);
    let mut count = 0;
    if unsafe { GetProcessHandleCount(process.0, &mut count) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if count > 65536 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut snapshot = ptr::null_mut();
    check(unsafe { PssCaptureSnapshot(process.0, PSS_CAPTURE_HANDLES, 0, &mut snapshot) })?;
    let snapshot = Snapshot(snapshot);
    let mut marker = ptr::null_mut();
    check(unsafe { PssWalkMarkerCreate(ptr::null(), &mut marker) })?;
    let marker = Marker(marker);
    let mut descriptors = Vec::new();
    for _ in 0..65536 {
        let mut entry = PSS_HANDLE_ENTRY::default();
        let status = unsafe {
            PssWalkSnapshot(
                snapshot.0,
                PSS_WALK_HANDLES,
                marker.0,
                (&mut entry as *mut PSS_HANDLE_ENTRY).cast(),
                size_of::<PSS_HANDLE_ENTRY>() as u32,
            )
        };
        if status == ERROR_NO_MORE_ITEMS {
            break;
        }
        check(status)?;
        let Ok(fd) = i32::try_from(entry.Handle as usize) else {
            continue;
        };
        let mut duplicate = ptr::null_mut();
        if unsafe {
            DuplicateHandle(
                process.0,
                entry.Handle,
                GetCurrentProcess(),
                &mut duplicate,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            continue;
        }
        let duplicate = Owned(duplicate);
        if unsafe { GetFileType(duplicate.0) } != FILE_TYPE_DISK {
            continue;
        }
        // PSS does not populate file-object names. Resolve disk-file handles
        // explicitly inside the helper's time-limited inspection child.
        let mut path = vec![0u16; 32768];
        let length = unsafe {
            GetFinalPathNameByHandleW(
                duplicate.0,
                path.as_mut_ptr(),
                path.len() as u32,
                FILE_NAME_OPENED | VOLUME_NAME_DOS,
            )
        } as usize;
        if length == 0 || length >= path.len() {
            continue;
        }
        let path = &path[..length];
        descriptors.push(FileDescriptorInfo {
            fd,
            kind: "file".into(),
            path: String::from_utf16_lossy(path),
        });
        if descriptors.len() == 4096 {
            break;
        }
    }
    descriptors.sort_by_key(|d| d.fd);
    Ok(descriptors)
}

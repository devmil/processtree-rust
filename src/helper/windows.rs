use std::io::{self, Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::{
    Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW, SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::Pipes::*;

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}
pub struct Stream(HANDLE);
// Owned kernel handle. The listener/stream is moved, never accessed concurrently.
unsafe impl Send for Stream {}
impl Drop for Stream {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
fn error() -> io::Error {
    let code = unsafe { GetLastError() };
    match code {
        ERROR_NO_DATA | ERROR_PIPE_LISTENING | ERROR_PIPE_BUSY => io::ErrorKind::WouldBlock.into(),
        _ => io::Error::from_raw_os_error(code as i32),
    }
}
impl Read for Stream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut read = 0;
        if unsafe {
            ReadFile(
                self.0,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                &mut read,
                ptr::null_mut(),
            )
        } == 0
        {
            if unsafe { GetLastError() } == ERROR_BROKEN_PIPE {
                return Ok(0);
            }
            return Err(error());
        }
        Ok(read as usize)
    }
}
impl Write for Stream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let mut written = 0;
        if unsafe {
            WriteFile(
                self.0,
                buffer.as_ptr(),
                buffer.len() as u32,
                &mut written,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(error());
        }
        if written == 0 && !buffer.is_empty() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        Ok(written as usize)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub fn connect(path: &Path) -> io::Result<Stream> {
    // Exclude FILE_CREATE_PIPE_INSTANCE from generic-write's mapped rights.
    let handle = unsafe {
        CreateFileW(
            wide(path).as_ptr(),
            FILE_GENERIC_READ | (FILE_GENERIC_WRITE & !FILE_CREATE_PIPE_INSTANCE),
            0,
            ptr::null(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(error());
    }
    let stream = Stream(handle);
    let mode = PIPE_READMODE_BYTE | PIPE_NOWAIT;
    if unsafe { SetNamedPipeHandleState(stream.0, &mode, ptr::null(), ptr::null()) } == 0 {
        return Err(error());
    }
    Ok(stream)
}
pub struct Listener {
    path: PathBuf,
    pipe: Option<Stream>,
}
impl Listener {
    pub fn bind(path: &Path) -> io::Result<Self> {
        Ok(Self {
            path: path.to_owned(),
            pipe: Some(create(path, true)?),
        })
    }
    pub fn accept(&mut self) -> io::Result<Stream> {
        if self.pipe.is_none() {
            self.pipe = Some(create(&self.path, true)?);
        }
        let pipe = self.pipe.as_ref().unwrap();
        if unsafe { ConnectNamedPipe(pipe.0, ptr::null_mut()) } == 0
            && unsafe { GetLastError() } != ERROR_PIPE_CONNECTED
        {
            return Err(error());
        }
        let connected = self.pipe.take().unwrap();
        self.pipe = Some(create(&self.path, false)?);
        Ok(connected)
    }
}
fn create(path: &Path, first: bool) -> io::Result<Stream> {
    // Authenticated local users can read/write requests, but cannot create a
    // competing server instance. The owner can create subsequent instances
    // even for an unprivileged diagnostic server. Service ownership remains
    // SYSTEM/Administrators. Remote clients are rejected by the pipe.
    let sddl: Vec<u16> = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)(A;;0x12019b;;;AU)"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut descriptor = ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(error());
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let pipe = unsafe {
        CreateNamedPipeW(
            wide(path).as_ptr(),
            PIPE_ACCESS_DUPLEX
                | if first {
                    FILE_FLAG_FIRST_PIPE_INSTANCE
                } else {
                    0
                },
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
            5,
            65536,
            1024,
            0,
            &attributes,
        )
    };
    let result = if pipe == INVALID_HANDLE_VALUE {
        Err(error())
    } else {
        Ok(Stream(pipe))
    };
    unsafe {
        LocalFree(descriptor);
    }
    result
}

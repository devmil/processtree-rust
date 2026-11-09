use std::fs;
use std::io;
use std::os::unix::{
    fs::PermissionsExt,
    net::{UnixListener, UnixStream},
};
use std::path::{Path, PathBuf};
pub fn connect(endpoint: &Path) -> io::Result<UnixStream> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    let bytes = endpoint.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    address.sun_family = libc::AF_UNIX as _;
    for (out, byte) in address.sun_path.iter_mut().zip(bytes) {
        *out = *byte as _;
    }
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    stream.set_nonblocking(true)?;
    unsafe {
        libc::fcntl(stream.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC);
    }
    if unsafe {
        libc::connect(
            stream.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            std::mem::size_of::<libc::sockaddr_un>() as _,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(stream)
}
pub struct Listener {
    listener: UnixListener,
    path: PathBuf,
}
impl Listener {
    pub fn bind(path: &Path) -> io::Result<Self> {
        // The caller owns a root-writable runtime directory. Never unlink an
        // endpoint belonging to a live helper.
        if path.exists() {
            match connect(path) {
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {}
                _ => return Err(io::ErrorKind::AddrInUse.into()),
            }
            if !fs::symlink_metadata(path)?.file_type().is_socket() {
                return Err(io::ErrorKind::AlreadyExists.into());
            }
            fs::remove_file(path)?;
        }
        let listener = UnixListener::bind(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o666))?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            path: path.to_owned(),
        })
    }
    pub fn accept(&mut self) -> io::Result<UnixStream> {
        let (stream, _) = self.listener.accept()?;
        stream.set_nonblocking(true)?;
        Ok(stream)
    }
}
use std::os::unix::fs::FileTypeExt;
impl Drop for Listener {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

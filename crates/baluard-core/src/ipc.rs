//! Client-side IPC transport to the daemon.
//!
//! Unix: a Unix socket at `paths::socket_path()`. Windows: a named pipe —
//! std has no named-pipe API, so the client goes through `windows-sys`
//! here; the daemon's server side uses tokio's named-pipe support.

use std::io;
use std::path::Path;
use std::time::Duration;

/// Blocking client connection to the daemon. Sync on purpose: the CLI and
/// the NMH worker threads are not async, and the desktop client must not
/// freeze the UI on a stalled daemon (hence the timeouts).
pub struct IpcStream {
    #[cfg(unix)]
    inner: std::os::unix::net::UnixStream,
    #[cfg(windows)]
    handle: windows_sys::Win32::Foundation::HANDLE, // isize
    #[cfg(windows)]
    read_deadline: Option<std::time::Instant>,
}

// The HANDLE is owned (closed on drop) and never shared; reads and writes
// happen from whichever thread owns the stream.
unsafe impl Send for IpcStream {}
unsafe impl Sync for IpcStream {}

impl IpcStream {
    #[cfg(unix)]
    pub fn connect(path: &Path) -> io::Result<Self> {
        Ok(Self {
            inner: std::os::unix::net::UnixStream::connect(path)?,
        })
    }

    #[cfg(windows)]
    pub fn connect(path: &Path) -> io::Result<Self> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::{
            ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, GENERIC_READ, GENERIC_WRITE,
            INVALID_HANDLE_VALUE,
        };
        use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING};
        use windows_sys::Win32::System::Pipes::WaitNamedPipeW;

        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // ERROR_PIPE_BUSY means a live daemon owns every instance of the
        // pipe: wait for a free instance instead of reporting the daemon
        // dead. That wait is also what keeps the daemon's startup liveness
        // probe truthful.
        for attempt in 0..3u32 {
            let handle = unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    0,
                    std::ptr::null_mut(),
                )
            };
            if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
                return Ok(Self {
                    handle,
                    read_deadline: None,
                });
            }
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) && attempt < 2 {
                unsafe {
                    WaitNamedPipeW(wide.as_ptr(), 100);
                }
                continue;
            }
            if err.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) {
                return Err(io::Error::new(io::ErrorKind::NotFound, err));
            }
            return Err(err);
        }
        Err(io::Error::new(io::ErrorKind::TimedOut, "pipe is busy"))
    }

    /// Half-close after sending a framed request. Windows named pipes have
    /// no half-close; the varint frame prefix already tells the daemon how
    /// much to read, and dropping the stream gives it its EOF.
    pub fn shutdown(&mut self) -> io::Result<()> {
        #[cfg(unix)]
        {
            self.inner.shutdown(std::net::Shutdown::Write)
        }
        #[cfg(windows)]
        {
            Ok(())
        }
    }

    /// Bound I/O so a stalled daemon cannot wedge the caller forever.
    /// Windows enforces the read bound by polling `PeekNamedPipe` against
    /// the deadline; a blocking-mode pipe has no write timeout, and the
    /// wedged-daemon write risk is bounded by the OS pipe buffer.
    pub fn set_timeouts(&mut self, read: Duration, write: Duration) -> io::Result<()> {
        #[cfg(unix)]
        {
            self.inner.set_read_timeout(Some(read))?;
            self.inner.set_write_timeout(Some(write))?;
            Ok(())
        }
        #[cfg(windows)]
        {
            let _ = write;
            self.read_deadline = Some(std::time::Instant::now() + read);
            Ok(())
        }
    }
}

impl io::Read for IpcStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        #[cfg(unix)]
        return io::Read::read(&mut self.inner, buf);
        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::ERROR_BROKEN_PIPE;
            use windows_sys::Win32::Storage::FileSystem::ReadFile;
            use windows_sys::Win32::System::Pipes::PeekNamedPipe;

            if buf.is_empty() {
                return Ok(0);
            }
            // Poll-with-deadline: a plain ReadFile on a blocking pipe has
            // no timeout, so check availability first and sleep between
            // checks. One reader per connection, so the peek-to-read gap
            // cannot lose data to a competing reader.
            loop {
                let mut available: u32 = 0;
                let ok = unsafe {
                    PeekNamedPipe(
                        self.handle,
                        std::ptr::null_mut(),
                        0,
                        std::ptr::null_mut(),
                        &mut available,
                        std::ptr::null_mut(),
                    )
                };
                if ok == 0 {
                    return Err(io::Error::last_os_error());
                }
                if available > 0 {
                    break;
                }
                if let Some(deadline) = self.read_deadline {
                    if std::time::Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "daemon read timed out",
                        ));
                    }
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let mut read: u32 = 0;
            let ok = unsafe {
                ReadFile(
                    self.handle,
                    buf.as_mut_ptr().cast(),
                    buf.len() as u32,
                    &mut read,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                let err = io::Error::last_os_error();
                // Broken pipe = the daemon closed the connection: report a
                // clean EOF like a socket read would.
                if err.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) {
                    return Ok(0);
                }
                return Err(err);
            }
            Ok(read as usize)
        }
    }
}

impl io::Write for IpcStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        #[cfg(unix)]
        return io::Write::write(&mut self.inner, buf);
        #[cfg(windows)]
        {
            use windows_sys::Win32::Storage::FileSystem::WriteFile;

            let mut written: u32 = 0;
            let ok = unsafe {
                WriteFile(
                    self.handle,
                    buf.as_ptr().cast(),
                    buf.len() as u32,
                    &mut written,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(written as usize)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        // Pipe writes are delivered by the OS; there is no user-space
        // buffer to push out.
        Ok(())
    }
}

impl Drop for IpcStream {
    fn drop(&mut self) {
        #[cfg(windows)]
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.handle);
        }
    }
}

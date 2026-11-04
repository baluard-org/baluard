//! Client-side IPC transport to the daemon.
//!
//! Unix: a Unix socket at `paths::socket_path()`. Windows: a named pipe —
//! std has no named-pipe API, so the client goes through `windows-sys`
//! here; the daemon's server side uses tokio's named-pipe support.

use std::io;
use std::path::Path;
use std::time::Duration;

/// Frames larger than this are refused: mirrors the daemon's
/// MAX_FRAME_SIZE so a bogus length prefix cannot balloon an allocation.
pub const MAX_FRAME_LEN: usize = 4 * 1024 * 1024;

/// Blocking client connection to the daemon. Sync on purpose: the CLI and
/// the NMH worker threads are not async, and the desktop client must not
/// freeze the UI on a stalled daemon (hence the timeouts).
pub struct IpcStream {
    #[cfg(unix)]
    inner: std::os::unix::net::UnixStream,
    #[cfg(windows)]
    handle: windows_sys::Win32::Foundation::HANDLE,
    #[cfg(windows)]
    read_timeout: Option<Duration>,
}

// The HANDLE is owned (closed on drop) and never shared; reads and writes
// happen from whichever thread owns the stream.
#[cfg(windows)]
unsafe impl Send for IpcStream {}
#[cfg(windows)]
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
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, OPEN_EXISTING, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
        };
        use windows_sys::Win32::System::Pipes::{GetNamedPipeServerProcessId, WaitNamedPipeW};

        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // ERROR_PIPE_BUSY means a live daemon owns every instance of the
        // pipe: wait for a free instance instead of reporting the daemon
        // dead. That wait is also what keeps the daemon's startup liveness
        // probe truthful.
        let mut handle = std::ptr::null_mut();
        for attempt in 0..3u32 {
            handle = unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    // SECURITY_IDENTIFICATION: the server may identify this
                    // client's token but never impersonate it.
                    SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                    std::ptr::null_mut(),
                )
            };
            if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
                break;
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
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "pipe is busy"));
        }

        // The pipe namespace is machine-global: any local account can
        // create a server with any name first, and first_pipe_instance
        // only guards the daemon-to-daemon race. Before writing a byte,
        // verify the process on the other end runs as this user; a rogue
        // same-named server would otherwise receive unlock payloads.
        let mut server_pid: u32 = 0;
        if unsafe { GetNamedPipeServerProcessId(handle, &mut server_pid) } == 0 {
            let err = io::Error::last_os_error();
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(handle);
            }
            return Err(err);
        }
        if !server_is_same_user(server_pid) {
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(handle);
            }
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "pipe server does not belong to this user; refusing to talk to it",
            ));
        }

        Ok(Self {
            handle,
            read_timeout: None,
        })
    }

    /// Half-close after sending a framed request. Windows named pipes have
    /// no half-close; read_frame() bounds the response by its length
    /// prefix, so nothing waits for an EOF that never comes.
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

    /// Bound I/O so a stalled daemon cannot wedge the caller forever. On
    /// unix this maps to the socket read/write timeouts; on Windows the
    /// bound applies per read call (peek-poll against a fresh deadline),
    /// which matches unix per-call semantics. A blocking-mode pipe has no
    /// write timeout; a wedged daemon can stall a large write, and the
    /// honest bound for that is a watchdog with CancelIoEx, which nothing
    /// here needs yet.
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
            self.read_timeout = Some(read);
            Ok(())
        }
    }

    /// Read one length-prefixed frame (varint header + payload). Clients
    /// must use this instead of read_to_end: a Windows pipe cannot be
    /// half-closed by the client, so the daemon would keep the connection
    /// open after answering and read_to_end would hang until the timeout.
    pub fn read_frame(&mut self, max_len: usize) -> io::Result<Vec<u8>> {
        use std::io::Read as _;
        let mut len: u64 = 0;
        let mut shift = 0u32;
        let mut byte = [0u8; 1];
        let mut out = Vec::new();
        loop {
            if shift >= 70 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "response varint overflow",
                ));
            }
            let n = self.read(&mut byte)?;
            if n == 0 {
                if out.is_empty() {
                    return Ok(out);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected EOF while reading varint length",
                ));
            }
            out.push(byte[0]);
            len |= ((byte[0] & 0x7F) as u64) << shift;
            if byte[0] & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        if len as usize > max_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("response frame too large: {len} > {max_len}"),
            ));
        }
        let header_len = out.len();
        out.resize(header_len + len as usize, 0);
        self.read_exact(&mut out[header_len..])?;
        Ok(out)
    }
}

impl io::Read for IpcStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        #[cfg(unix)]
        return io::Read::read(&mut self.inner, buf);
        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::{ERROR_BROKEN_PIPE, ERROR_PIPE_NOT_CONNECTED};
            use windows_sys::Win32::Storage::FileSystem::ReadFile;
            use windows_sys::Win32::System::Pipes::PeekNamedPipe;

            if buf.is_empty() {
                return Ok(0);
            }
            let deadline = self.read_timeout.map(|t| std::time::Instant::now() + t);
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
                    let err = io::Error::last_os_error();
                    // Broken pipe = the daemon closed the connection:
                    // report a clean EOF like a socket read would.
                    if err.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32)
                        || err.raw_os_error() == Some(ERROR_PIPE_NOT_CONNECTED as i32)
                    {
                        return Ok(0);
                    }
                    return Err(err);
                }
                if available > 0 {
                    break;
                }
                match deadline {
                    Some(d) if std::time::Instant::now() >= d => {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "daemon read timed out",
                        ));
                    }
                    _ => std::thread::sleep(Duration::from_millis(20)),
                }
            }
            let len = buf.len().min(u32::MAX as usize) as u32;
            let mut read: u32 = 0;
            let ok = unsafe {
                ReadFile(
                    self.handle,
                    buf.as_mut_ptr(),
                    len,
                    &mut read,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                let err = io::Error::last_os_error();
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

            let len = buf.len().min(u32::MAX as usize) as u32;
            let mut written: u32 = 0;
            let ok = unsafe {
                WriteFile(
                    self.handle,
                    buf.as_ptr(),
                    len,
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

#[cfg(windows)]
/// "S-1-5-..." string for the current process token's user SID, parsed
/// from the raw SID bytes. Pipe names are machine-global, so the SID
/// (not the spoofable USERNAME env) segments them per user.
pub fn windows_pipe_user_suffix() -> String {
    let Some(sid) = own_sid() else {
        return "default".into();
    };
    sid_string(&sid)
}

/// SECURITY_ATTRIBUTES granting GENERIC_ALL only to this user's SID.
/// The CreateNamedPipe default DACL hands read access to Everyone, which
/// would let any local account hold a connected instance open. The daemon
/// passes this to every pipe instance it creates.
#[cfg(windows)]
pub fn user_dacl_security_attributes() -> Option<UserSecurityAttributes> {
    use windows_sys::Win32::Foundation::GENERIC_ALL;
    use windows_sys::Win32::Security::{
        ACL, ACL_REVISION, AddAccessAllowedAceEx, InitializeAcl, InitializeSecurityDescriptor,
        SetSecurityDescriptorDacl,
    };
    use windows_sys::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;

    let sid = own_sid()?;
    let mut acl_buf = [0u8; 512];
    let acl_len = 16 + 8 + 8 + sid.len();
    // ACL header + ACCESS_ALLOWED_ACE header + the SID; 512 covers
    // every SID this process can own.
    if acl_len > acl_buf.len() {
        return None;
    }
    unsafe {
        let mut sd: SECURITY_DESCRIPTOR = std::mem::zeroed();
        if InitializeSecurityDescriptor(&mut sd as *mut _ as *mut _, SECURITY_DESCRIPTOR_REVISION)
            == 0
        {
            return None;
        }
        if InitializeAcl(
            acl_buf.as_mut_ptr() as *mut ACL,
            acl_len as u32,
            ACL_REVISION,
        ) == 0
        {
            return None;
        }
        if AddAccessAllowedAceEx(
            acl_buf.as_mut_ptr() as *mut ACL,
            ACL_REVISION,
            0,
            GENERIC_ALL,
            sid.as_ptr() as *mut _,
        ) == 0
        {
            return None;
        }
        if SetSecurityDescriptorDacl(
            &mut sd as *mut _ as *mut _,
            1,
            acl_buf.as_ptr() as *const ACL,
            0,
        ) == 0
        {
            return None;
        }
        Some(UserSecurityAttributes {
            sd,
            acl: acl_buf,
            sa: SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: std::ptr::null_mut(), // set via ptr method below
                bInheritHandle: 0,
            },
        })
    }
}

#[cfg(windows)]
mod security {
    pub use windows_sys::Win32::Security::{SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR};
}
#[cfg(windows)]
use security::{SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR};

/// Owns the SD + ACL backing the pointer handed to pipe creation. The
/// daemon must keep this alive for the duration of each create call.
#[cfg(windows)]
pub struct UserSecurityAttributes {
    sd: SECURITY_DESCRIPTOR,
    acl: [u8; 512],
    sa: SECURITY_ATTRIBUTES,
}

#[cfg(windows)]
impl UserSecurityAttributes {
    pub fn as_ptr(&mut self) -> *mut SECURITY_ATTRIBUTES {
        // Re-point the SD's DACL after the move: the stored Dacl still
        // references the buffer's pre-move stack slot.
        use windows_sys::Win32::Security::SetSecurityDescriptorDacl;
        unsafe {
            SetSecurityDescriptorDacl(
                &mut self.sd as *mut _ as *mut _,
                1,
                self.acl.as_ptr() as *const _,
                0,
            );
        }
        self.sa.lpSecurityDescriptor = &mut self.sd as *mut _ as *mut _;
        &mut self.sa
    }
}

/// Raw SID bytes for this process's token user, empty on failure.
#[cfg(windows)]
fn own_sid() -> Option<Vec<u8>> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{
        GetLengthSid, GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return None;
        }
        let mut len = 0u32;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len);
        let mut buf = vec![0u8; len as usize];
        let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr() as *mut _, len, &mut len);
        CloseHandle(token);
        if ok == 0 {
            return None;
        }
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        let psid = user.User.Sid;
        // TokenUser.User.Sid points into `buf`; copy from the pointer's
        // target, not from the buffer start (which holds the header).
        let n = GetLengthSid(psid) as usize;
        let mut out = vec![0u8; n];
        std::ptr::copy_nonoverlapping(psid as *const u8, out.as_mut_ptr(), n);
        Some(out)
    }
}

/// Render raw SID bytes as the "S-1-5-..." text form without Win32 allocs.
#[cfg(windows)]
fn sid_string(sid: &[u8]) -> String {
    // SID layout: revision u8, 48-bit identifier authority (big endian in
    // 6 bytes), subauthority count u8, then u32 subauthorities LE.
    if sid.len() < 8 {
        return "default".into();
    }
    let count = sid[1] as usize;
    if sid.len() < 8 + count * 4 {
        return "default".into();
    }
    let mut authority: u64 = 0;
    for &b in &sid[2..8] {
        authority = (authority << 8) | b as u64;
    }
    let mut out = format!("S-{}-{authority}", sid[0]);
    for i in 0..count {
        let sub = u32::from_le_bytes(sid[8 + i * 4..12 + i * 4].try_into().unwrap());
        out.push_str(&format!("-{sub}"));
    }
    out
}

/// True when `pid` runs under this process token's user SID. Any failure
/// in the chain resolves to false: fail closed.
#[cfg(windows)]
fn server_is_same_user(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{
        EqualSid, GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    unsafe {
        let Some(own) = own_sid() else {
            return false;
        };
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process.is_null() {
            return false;
        }
        let mut token = std::ptr::null_mut();
        let ok = OpenProcessToken(process, TOKEN_QUERY, &mut token);
        CloseHandle(process);
        if ok == 0 {
            return false;
        }
        let mut len = 0u32;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len);
        let mut buf = vec![0u8; len as usize];
        let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr() as *mut _, len, &mut len);
        CloseHandle(token);
        if ok == 0 {
            return false;
        }
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        let theirs = user.User.Sid;
        EqualSid(own.as_ptr() as *mut _, theirs) != 0
    }
}

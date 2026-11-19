#[cfg(any(target_os = "macos", target_os = "ios"))]
use libc::{RTAX_DST, RTAX_IFP};
use snafu::{Backtrace, ResultExt, Snafu};
use std::os::unix::io::FromRawFd;
use tokio::{io::AsyncReadExt, sync::mpsc};
use tokio_util::task::AbortOnDropHandle;
use tracing::{trace, warn};

use super::actor::NetworkMessage;
#[cfg(any(target_os = "freebsd", target_os = "netbsd", target_os = "openbsd"))]
use crate::interfaces::bsd::{RTAX_DST, RTAX_IFP};
use crate::{interfaces::bsd::WireMessage, ip::is_link_local};

#[derive(Debug)]
pub(super) struct RouteMonitor {
    _handle: AbortOnDropHandle<()>,
}

#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("IO"))]
    Io {
        source: std::io::Error,
        backtrace: Option<Backtrace>,
    },
}

fn create_socket() -> std::io::Result<tokio::net::UnixStream> {
    // netwatch 0.5.0 as published uses socket2 0.6-only APIs here
    // (Type::RAW behind socket2's "all" feature, and From<Socket> for the
    // std UnixStream, which never existed in 0.5.x), so a macOS build of
    // the iroh 0.35 tree cannot compile it. Raw libc call keeps the crate
    // on socket2 0.5.x for the rest of its API.
    let fd = unsafe { libc::socket(libc::AF_ROUTE, libc::SOCK_RAW, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let socket_std = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
    socket_std.set_nonblocking(true)?;
    let socket: tokio::net::UnixStream = socket_std.try_into()?;

    trace!("AF_ROUTE socket bound");

    Ok(socket)
}

impl RouteMonitor {
    pub(super) fn new(sender: mpsc::Sender<NetworkMessage>) -> Result<Self, Error> {
        let mut socket = create_socket().context(IoSnafu)?;
        let handle = tokio::task::spawn(async move {
            trace!("AF_ROUTE monitor started");

            // TODO: cleaner shutdown
            let mut buffer = vec![0u8; 2048];
            loop {
                match socket.read(&mut buffer).await {
                    Ok(read) => {
                        trace!("AF_ROUTE: read {} bytes", read);
                        match super::super::interfaces::bsd::parse_rib(
                            libc::NET_RT_DUMP,
                            &buffer[..read],
                        ) {
                            Ok(msgs) => {
                                if contains_interesting_message(&msgs) {
                                    sender.send(NetworkMessage::Change).await.ok();
                                }
                            }
                            Err(err) => {
                                warn!("AF_ROUTE: failed to parse rib: {:?}", err);
                            }
                        }
                    }
                    Err(err) => {
                        warn!("AF_ROUTE: error reading: {:?}", err);
                        // recreate socket, as it is likely in an invalid state
                        // TODO: distinguish between different errors?
                        match create_socket() {
                            Ok(new_socket) => {
                                socket = new_socket;
                            }
                            Err(err) => {
                                warn!("AF_ROUTE: unable to bind a new socket: {:?}", err);
                                // TODO: what to do here?
                            }
                        }
                    }
                }
            }
        });

        Ok(RouteMonitor {
            _handle: AbortOnDropHandle::new(handle),
        })
    }
}

fn contains_interesting_message(msgs: &[WireMessage]) -> bool {
    msgs.iter().any(is_interesting_message)
}

pub(super) fn is_interesting_message(msg: &WireMessage) -> bool {
    match msg {
        WireMessage::InterfaceMulticastAddr(_) => true,
        WireMessage::Interface(_) => false,
        WireMessage::InterfaceAddr(msg) => {
            if let Some(addr) = msg.addrs.get(RTAX_IFP as usize) {
                if let Some(name) = addr.name() {
                    if !is_interesting_interface(name) {
                        return false;
                    }
                }
            }
            true
        }
        WireMessage::Route(msg) => {
            // Ignore local unicast
            if let Some(addr) = msg.addrs.get(RTAX_DST as usize) {
                if let Some(ip) = addr.ip() {
                    if is_link_local(ip) {
                        return false;
                    }
                }
            }

            true
        }
        WireMessage::InterfaceAnnounce(_) => false,
    }
}

pub(super) fn is_interesting_interface(name: &str) -> bool {
    let base_name = name.trim_end_matches("0123456789");
    if base_name == "llw" || base_name == "awdl" || base_name == "ipsec" {
        return false;
    }

    true
}

//! Spike E test fixture: the "phone" side. Rust tokio + tokio-tungstenite
//! WebSocket server acting as the Noise IK RESPONDER.
//!
//! Two listeners:
//!   wss://127.0.0.1:17844  (TLS with a self-signed cert generated at startup;
//!                           PEMs written to run/ for the record)
//!   ws://127.0.0.1:17845   (plaintext fallback)
//!
//! Per-connection flow (sequential, matching background.js):
//!   msg1 -> msg2(+nonce) -> echo frame (nonce verified) -> 2 frames
//!   responder->initiator, each echoed by the initiator, then 2 frames
//!   initiator->responder -> "SPIKE-E-ALL-VERIFIED"
//!
//! Log markers (the pass oracle):
//!   SPIKE-E CONNECTION-RECEIPT   socket accepted (SW/event page reached us)
//!   SPIKE-E HANDSHAKE-COMPLETE   IK handshake + nonce echo verified
//!   SPIKE-E FRAME-VERIFY-OK      transport frame decrypted, payload matched
//!   SPIKE-E TEST-OK              full session, all verifications green
//!   SPIKE-E SESSION-ERROR        socket ran but the protocol failed
use std::error::Error;
use std::fmt;
use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type AnyError = Box<dyn Error + Send + Sync>;

use futures_util::{SinkExt, StreamExt};
use snow_spike::Responder;
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

const WSS_PORT: u16 = 17844;
const WS_PORT: u16 = 17845;
const READ_TIMEOUT: Duration = Duration::from_secs(30);

fn log(msg: &str) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "SPIKE-E {} {msg}", now.as_secs_f64().round() as u64);
    let _ = out.flush();
}

#[derive(Debug)]
enum SessError {
    Closed(String),
    Timeout,
    Handshake(snow_spike::SpikeError),
    PayloadMismatch { expected: String, got: Vec<u8> },
    Io(std::io::Error),
}

impl fmt::Display for SessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed(d) => write!(f, "closed: {d}"),
            Self::Timeout => write!(f, "read timeout"),
            Self::Handshake(e) => write!(f, "{e}"),
            Self::PayloadMismatch { expected, got } => {
                write!(f, "payload mismatch: want {expected:?}, got {got:02x?}")
            }
            Self::Io(e) => write!(f, "io: {e}"),
        }
    }
}

async fn recv_bin<S>(ws: &mut WebSocketStream<S>) -> Result<Vec<u8>, SessError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        match timeout(READ_TIMEOUT, ws.next()).await {
            Ok(Some(Ok(Message::Binary(b)))) => return Ok(b.to_vec()),
            Ok(Some(Ok(Message::Close(c)))) => return Err(SessError::Closed(format!("{c:?}"))),
            Ok(Some(Ok(_))) => continue, // ping/pong/text ignored
            Ok(Some(Err(e))) => return Err(SessError::Io(std::io::Error::other(e.to_string()))),
            Ok(None) => return Err(SessError::Closed("stream end".into())),
            Err(_) => return Err(SessError::Timeout),
        }
    }
}

async fn send_bin<S>(ws: &mut WebSocketStream<S>, bytes: Vec<u8>) -> Result<(), SessError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    ws.send(Message::Binary(bytes.into()))
        .await
        .map_err(|e| SessError::Io(std::io::Error::other(e.to_string())))
}

fn expect(plain: Vec<u8>, expected: &str) -> Result<(), SessError> {
    if plain == expected.as_bytes() {
        Ok(())
    } else {
        Err(SessError::PayloadMismatch {
            expected: expected.to_string(),
            got: plain,
        })
    }
}

async fn run_session<S>(mut ws: WebSocketStream<S>, endpoint: &'static str)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let started = Instant::now();
    log(&format!("CONNECTION-RECEIPT endpoint={endpoint}"));
    let res = session_body(&mut ws, endpoint).await;
    let _ = ws.close(None).await;
    match res {
        Ok(()) => log(&format!(
            "TEST-OK endpoint={endpoint} elapsed_ms={}",
            started.elapsed().as_millis()
        )),
        Err(e) => log(&format!("SESSION-ERROR endpoint={endpoint} reason={e}")),
    }
}

async fn session_body<S>(ws: &mut WebSocketStream<S>, endpoint: &'static str) -> Result<(), SessError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut responder = Responder::new().map_err(SessError::Handshake)?;

    // 1. msg1 -> msg2 (fresh nonce payload)
    let msg1 = recv_bin(ws).await?;
    let msg2 = responder.read_msg1(&msg1).map_err(SessError::Handshake)?;
    send_bin(ws, msg2).await?;

    // 2. echo frame: transport counter 0 must decrypt AND equal the nonce
    let echo = recv_bin(ws).await?;
    responder.read_echo(&echo).map_err(SessError::Handshake)?;
    log(&format!("HANDSHAKE-COMPLETE endpoint={endpoint}"));

    // 3. two frames responder -> initiator, echoed back by the initiator
    for label in ["spike-e-up-1", "spike-e-up-2"] {
        let frame = responder.write_frame(label.as_bytes()).map_err(SessError::Handshake)?;
        send_bin(ws, frame).await?;
        let reply = recv_bin(ws).await?;
        let plain = responder.read_frame(&reply).map_err(SessError::Handshake)?;
        expect(plain, label)?;
        log(&format!("FRAME-VERIFY-OK endpoint={endpoint} dir=r2i frame={label}"));
    }

    // 4. two frames initiator -> responder
    for label in ["spike-e-dn-1", "spike-e-dn-2"] {
        let frame = recv_bin(ws).await?;
        let plain = responder.read_frame(&frame).map_err(SessError::Handshake)?;
        expect(plain, label)?;
        log(&format!("FRAME-VERIFY-OK endpoint={endpoint} dir=i2r frame={label}"));
    }

    // 5. final marker (the initiator looks for it)
    let done = responder.write_frame(b"SPIKE-E-ALL-VERIFIED").map_err(SessError::Handshake)?;
    send_bin(ws, done).await?;
    Ok(())
}

async fn plain_listener() -> Result<(), AnyError> {
    let listener = TcpListener::bind(("127.0.0.1", WS_PORT)).await?;
    log(&format!("LISTENING ws://127.0.0.1:{WS_PORT}"));
    loop {
        let (tcp, _peer) = listener.accept().await?;
        let ws = match tokio_tungstenite::accept_async(tcp).await {
            Ok(ws) => ws,
            Err(e) => {
                // a bad WS upgrade must not kill the listener
                log(&format!("ACCEPT-ERROR endpoint=ws reason={e}"));
                continue;
            }
        };
        tokio::spawn(run_session(ws, "ws"));
    }
}

async fn tls_listener(cert_der: Vec<u8>, key_der: Vec<u8>) -> Result<(), AnyError> {
    let certs = vec![rustls::pki_types::CertificateDer::from(cert_der)];
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(key_der);
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key.into())?;
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind(("127.0.0.1", WSS_PORT)).await?;
    log(&format!("LISTENING wss://127.0.0.1:{WSS_PORT} (self-signed)"));
    loop {
        let (tcp, _peer) = listener.accept().await?;
        let tls = match acceptor.accept(tcp).await {
            Ok(t) => t,
            Err(e) => {
                // a client cert-reject (alert/abort) must not kill the listener
                log(&format!("ACCEPT-ERROR endpoint=wss reason={e}"));
                continue;
            }
        };
        let ws = match tokio_tungstenite::accept_async(tls).await {
            Ok(ws) => ws,
            Err(e) => {
                log(&format!("ACCEPT-ERROR endpoint=wss reason={e}"));
                continue;
            }
        };
        tokio::spawn(run_session(ws, "wss"));
    }
}

#[tokio::main]
async fn main() -> Result<(), AnyError> {
    log("SERVER-START tether-responder (Noise IK responder over WebSocket)");

    let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()])?;
    let cert_der = ck.cert.der().to_vec();
    let key_der = ck.signing_key.serialize_der();
    // keep the PEMs for the record (run/); failure here is not fatal
    let _ = std::fs::create_dir_all("run");
    let _ = std::fs::write("run/tether-server-cert.pem", ck.cert.pem());
    let _ = std::fs::write("run/tether-server-key.pem", ck.signing_key.serialize_pem());
    log("SERVER-CERT generated (self-signed, CN=127.0.0.1), PEMs in run/");

    let t1 = tokio::spawn(tls_listener(cert_der, key_der));
    let t2 = tokio::spawn(plain_listener());
    let (r1, r2) = tokio::try_join!(t1, t2)?;
    r1?;
    r2?;
    Ok(())
}

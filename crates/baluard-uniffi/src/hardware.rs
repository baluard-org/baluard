//! Mobile security-key bridge. One foreign transport is installed for the
//! duration of one serialized vault operation; the FIDO store stays lazy, so
//! Argon2id finishes before Android opens NFC or USB.

use crate::{BaluardError, MobileVault};
use baluard_core::hwkey::attest::PackedAttestation;
use baluard_core::hwkey::ctap::apdu::{ApduError, ApduForm, Transceive};
use baluard_core::hwkey::ctap::ctaphid::{CtapHidError, HidLink};
use baluard_core::hwkey::ctap::protocol::{ClientError, CtapClient};
use baluard_core::hwkey::ctap::token;
use baluard_core::hwkey::fido::{FidoStore, Token, TokenError, TokenInfo};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum MobileTransportProtocol {
    Nfc,
    Usb,
}

/// Android implements this interface with IsoDep or UsbDeviceConnection.
/// The object is operation-scoped and `shutdown` always runs exactly once.
#[uniffi::export(with_foreign)]
pub trait MobileHardwareTransport: Send + Sync {
    fn protocol(&self) -> MobileTransportProtocol;
    fn supports_extended_apdu(&self) -> Result<bool, BaluardError>;
    /// NFC: one raw APDU in, raw response body plus SW1/SW2 out.
    fn transceive(&self, request: Vec<u8>) -> Result<Vec<u8>, BaluardError>;
    /// USB: one 65-byte CTAPHID report in either direction.
    fn write(&self, report: Vec<u8>) -> Result<(), BaluardError>;
    fn read(&self) -> Result<Vec<u8>, BaluardError>;
    fn shutdown(&self);
}

static ACTIVE_TRANSPORT: Mutex<Option<Arc<dyn MobileHardwareTransport>>> = Mutex::new(None);
// Every MobileVault path that can reach the device keys takes this lock.
// ACTIVE_TRANSPORT therefore belongs to exactly one operation and cannot be
// borrowed by a concurrent ordinary or security-key unlock.
pub(crate) static MOBILE_OPERATION_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

// The core store's probe collapses token errors into capability reasons, so the
// foreign transport's own failure text would never reach the caller. Record it
// at the callback boundary and let the operation wrappers prefer it.
static LAST_TRANSPORT_ERROR: Mutex<Option<String>> = Mutex::new(None);

fn record_transport_error(detail: String) {
    if let Ok(mut slot) = LAST_TRANSPORT_ERROR.lock() {
        *slot = Some(detail);
    }
}

fn take_transport_error() -> Option<String> {
    LAST_TRANSPORT_ERROR.lock().ok()?.take()
}
fn map_runtime_hardware_error(error: String) -> BaluardError {
    let detail = take_transport_error();
    let hardware_failure = error.starts_with("Connect a compatible security key.")
        || error.starts_with("This device has no usable security chip.")
        || error.contains("security key")
        || error.contains("security chip")
        || error.contains("chip is unavailable");
    match (hardware_failure, detail) {
        (true, Some(detail)) => BaluardError::SecurityKey { detail },
        _ => error.into(),
    }
}

fn map_core_hardware_error(error: baluard_core::error::BaluardError) -> BaluardError {
    let detail = take_transport_error();
    if baluard_core::error::is_hardware_error(&error) {
        if let Some(detail) = detail {
            return BaluardError::SecurityKey { detail };
        }
    }
    crate::map_unlock_error(error)
}

struct TransportScope;

impl TransportScope {
    fn enter(transport: Arc<dyn MobileHardwareTransport>) -> Self {
        *ACTIVE_TRANSPORT.lock().expect("transport lock") = Some(transport);
        if let Ok(mut slot) = LAST_TRANSPORT_ERROR.lock() {
            *slot = None;
        }
        baluard_core::hwkey::install(Arc::new(FidoStore::new(Box::new(MobileToken))));
        Self
    }
}

impl Drop for TransportScope {
    fn drop(&mut self) {
        if let Some(transport) = ACTIVE_TRANSPORT.lock().expect("transport lock").take() {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                transport.shutdown();
            }));
        }
        // The scope installed MobileToken in the core registry; a dead
        // transport left registered would fail every later registry
        // consult (fail-closed, but confusingly). Drop it with the scope.
        baluard_core::hwkey::uninstall();
    }
}

struct CallbackLink {
    transport: Arc<dyn MobileHardwareTransport>,
    callback_error: Mutex<Option<String>>,
}

impl CallbackLink {
    fn new(transport: Arc<dyn MobileHardwareTransport>) -> Self {
        Self {
            transport,
            callback_error: Mutex::new(None),
        }
    }

    fn remember(&self, error: BaluardError) {
        let detail = error.to_string();
        record_transport_error(detail.clone());
        *self.callback_error.lock().expect("callback error lock") = Some(detail);
    }

    fn map_operation_error(&self, error: TokenError) -> TokenError {
        let detail = self
            .callback_error
            .lock()
            .expect("callback error lock")
            .take();
        match (error, detail) {
            (TokenError::KeyMissing | TokenError::Device(_), Some(detail)) => {
                TokenError::Device(detail)
            }
            (error, _) => error,
        }
    }

    fn map_error(&self, error: ClientError) -> TokenError {
        match self
            .callback_error
            .lock()
            .expect("callback error lock")
            .take()
        {
            Some(detail) => TokenError::Device(detail),
            None => token::map_client_error(error),
        }
    }
}

impl Transceive for CallbackLink {
    fn transceive(&self, request: &[u8]) -> Result<(Vec<u8>, [u8; 2]), ApduError> {
        let response = self
            .transport
            .transceive(request.to_vec())
            .map_err(|error| {
                self.remember(error);
                ApduError::Transport
            })?;
        if response.len() < 2 {
            return Err(ApduError::Malformed);
        }
        let split = response.len() - 2;
        let sw = [response[split], response[split + 1]];
        Ok((response[..split].to_vec(), sw))
    }
}

impl HidLink for CallbackLink {
    fn write(&self, report: &[u8; 65]) -> Result<(), CtapHidError> {
        self.transport.write(report.to_vec()).map_err(|error| {
            self.remember(error);
            CtapHidError::Link
        })
    }

    fn read(&self) -> Result<[u8; 65], CtapHidError> {
        let response = self.transport.read().map_err(|error| {
            self.remember(error);
            CtapHidError::Link
        })?;
        response
            .as_slice()
            .try_into()
            .map_err(|_| CtapHidError::Malformed)
    }
}

struct MobileToken;

impl MobileToken {
    fn link() -> Result<CallbackLink, TokenError> {
        let transport = ACTIVE_TRANSPORT
            .lock()
            .map_err(|_| TokenError::Device("transport lock poisoned".into()))?
            .clone()
            .ok_or_else(|| TokenError::Device("security key transport is not active".into()))?;
        Ok(CallbackLink::new(transport))
    }

    fn with_client<R>(
        &self,
        operation: impl FnOnce(CtapClient<'_>) -> Result<R, TokenError>,
    ) -> Result<R, TokenError> {
        let link = Self::link()?;
        match link.transport.protocol() {
            MobileTransportProtocol::Nfc => {
                let extended = link
                    .transport
                    .supports_extended_apdu()
                    .map_err(|error| TokenError::Device(error.to_string()))?;
                let client =
                    CtapClient::new_apdu_form(&link, ApduForm::for_extended_support(extended))
                        .map_err(|error| link.map_error(error))?;
                operation(client).map_err(|error| link.map_operation_error(error))
            }
            MobileTransportProtocol::Usb => {
                let client = CtapClient::new(&link).map_err(|error| link.map_error(error))?;
                operation(client).map_err(|error| link.map_operation_error(error))
            }
        }
    }
}

impl Token for MobileToken {
    fn info(&self) -> Result<TokenInfo, TokenError> {
        self.with_client(token::token_info)
    }

    fn make_credential(&self, vault_id: Uuid) -> Result<PackedAttestation, TokenError> {
        self.with_client(|client| token::make_credential(client, vault_id))
    }

    fn get_secret(
        &self,
        credential_id: &[u8],
        salt: &[u8; 32],
    ) -> Result<zeroize::Zeroizing<[u8; 32]>, TokenError> {
        self.with_client(|client| token::get_secret(client, credential_id, salt))
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl MobileVault {
    /// Platform capability comes from Android (NFC or USB host support); no
    /// reader session opens for this status call.
    pub async fn hardware_status(&self, platform_capable: bool) -> Result<String, BaluardError> {
        let _operation = MOBILE_OPERATION_LOCK.lock().await;
        let raw = self.state.hw_status().await?;
        let mut status: serde_json::Value =
            serde_json::from_str(&raw).map_err(|e| BaluardError::Vault {
                detail: e.to_string(),
            })?;
        status["capable"] = platform_capable.into();
        status["backend"] = "fido2".into();
        status["reason"] = if platform_capable {
            serde_json::Value::Null
        } else {
            "nfc-or-usb-unavailable".into()
        };
        status["backends"] = serde_json::json!([{
            "backend": "fido2",
            "capable": platform_capable,
            "reason": if platform_capable { serde_json::Value::Null } else { "nfc-or-usb-unavailable".into() },
            "interaction": "per-use"
        }]);
        Ok(status.to_string())
    }

    pub async fn hardware_enable(
        &self,
        transport: Arc<dyn MobileHardwareTransport>,
    ) -> Result<String, BaluardError> {
        let _operation = MOBILE_OPERATION_LOCK.lock().await;
        let _scope = TransportScope::enter(transport);
        match self.state.hw_enable(false, Some("fido2".into())).await {
            Ok(response) => Ok(response),
            Err(error) => Err(map_runtime_hardware_error(error)),
        }
    }

    pub async fn hardware_disable(
        &self,
        transport: Arc<dyn MobileHardwareTransport>,
    ) -> Result<String, BaluardError> {
        let _operation = MOBILE_OPERATION_LOCK.lock().await;
        let _scope = TransportScope::enter(transport);
        match self.state.hw_disable().await {
            Ok(response) => Ok(response),
            Err(error) => Err(map_runtime_hardware_error(error)),
        }
    }

    pub async fn unlock_with_security_key(
        self: &Arc<Self>,
        master_password: String,
        transport: Arc<dyn MobileHardwareTransport>,
    ) -> Result<(), BaluardError> {
        let _operation = MOBILE_OPERATION_LOCK.lock().await;
        let _scope = TransportScope::enter(transport);
        let master_password = zeroize::Zeroizing::new(master_password);
        self.state
            .unlock(&master_password)
            .await
            .map_err(map_core_hardware_error)
    }

    pub async fn unlock_with_security_key_and_kek(
        self: &Arc<Self>,
        kek: Vec<u8>,
        transport: Arc<dyn MobileHardwareTransport>,
    ) -> Result<(), BaluardError> {
        let _operation = MOBILE_OPERATION_LOCK.lock().await;
        let _scope = TransportScope::enter(transport);
        let kek = zeroize::Zeroizing::new(kek);
        let mut arr = zeroize::Zeroizing::new([0u8; 32]);
        if kek.len() != 32 {
            return Err(BaluardError::InvalidInput {
                detail: "KEK must be 32 bytes".into(),
            });
        }
        arr.copy_from_slice(&kek);
        self.state
            .unlock_with_kek_lean(&arr)
            .await
            .map_err(map_core_hardware_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static ERROR_TEST_LOCK: Mutex<()> = Mutex::new(());
    use std::sync::atomic::{AtomicBool, Ordering};

    struct FailingTransport;

    impl MobileHardwareTransport for FailingTransport {
        fn protocol(&self) -> MobileTransportProtocol {
            MobileTransportProtocol::Nfc
        }
        fn supports_extended_apdu(&self) -> Result<bool, BaluardError> {
            Ok(false)
        }
        fn transceive(&self, _request: Vec<u8>) -> Result<Vec<u8>, BaluardError> {
            Err(BaluardError::Vault {
                detail: "hold the key steady".into(),
            })
        }
        fn write(&self, _report: Vec<u8>) -> Result<(), BaluardError> {
            unreachable!()
        }
        fn read(&self) -> Result<Vec<u8>, BaluardError> {
            unreachable!()
        }
        fn shutdown(&self) {}
    }

    #[test]
    fn callback_detail_survives_transport_mapping() {
        let _guard = ERROR_TEST_LOCK.lock().unwrap();
        let link = CallbackLink::new(Arc::new(FailingTransport));
        let error = match CtapClient::new_apdu_form(&link, ApduForm::Chained) {
            Ok(_) => panic!("failing transport unexpectedly connected"),
            Err(error) => error,
        };
        let mapped = link.map_error(error);
        assert!(
            matches!(mapped, TokenError::Device(detail) if detail.contains("hold the key steady"))
        );
    }

    #[test]
    fn transport_detail_never_replaces_a_credential_failure() {
        let _guard = ERROR_TEST_LOCK.lock().unwrap();
        record_transport_error("Turn on NFC and retry".into());
        let wrong =
            map_core_hardware_error(baluard_core::error::VaultError::PasswordMismatch.into());
        assert!(matches!(wrong, BaluardError::WrongPassword));
        let timeout =
            map_core_hardware_error(baluard_core::error::VaultError::HardwareTouchTimeout.into());
        assert!(matches!(timeout, BaluardError::SecurityKey { .. }));

        record_transport_error("Turn on NFC and retry".into());
        let wrong_runtime = map_runtime_hardware_error("master password incorrect".into());
        assert!(
            matches!(wrong_runtime, BaluardError::Vault { detail } if detail == "master password incorrect")
        );

        record_transport_error("Turn on NFC and retry".into());
        let probe = map_runtime_hardware_error("Connect a compatible security key.".into());
        assert!(
            matches!(probe, BaluardError::SecurityKey { detail } if detail == "Turn on NFC and retry")
        );
    }

    struct PanickingShutdown(AtomicBool);

    impl MobileHardwareTransport for PanickingShutdown {
        fn protocol(&self) -> MobileTransportProtocol {
            MobileTransportProtocol::Nfc
        }
        fn supports_extended_apdu(&self) -> Result<bool, BaluardError> {
            Ok(false)
        }
        fn transceive(&self, _request: Vec<u8>) -> Result<Vec<u8>, BaluardError> {
            unreachable!()
        }
        fn write(&self, _report: Vec<u8>) -> Result<(), BaluardError> {
            unreachable!()
        }
        fn read(&self) -> Result<Vec<u8>, BaluardError> {
            unreachable!()
        }
        fn shutdown(&self) {
            self.0.store(true, Ordering::SeqCst);
            panic!("foreign shutdown panic");
        }
    }

    #[test]
    fn scope_clears_transport_and_contains_shutdown_panics() {
        let _guard = ERROR_TEST_LOCK.lock().unwrap();
        let transport = Arc::new(PanickingShutdown(AtomicBool::new(false)));
        let flag = transport.clone();
        {
            let _scope = TransportScope::enter(transport);
            assert!(ACTIVE_TRANSPORT.lock().unwrap().is_some());
        }
        assert!(flag.0.load(Ordering::SeqCst));
        assert!(ACTIVE_TRANSPORT.lock().unwrap().is_none());
    }
}

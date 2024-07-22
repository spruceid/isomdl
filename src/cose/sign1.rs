use crate::cose::Cose;
use coset::cbor::Value;
use coset::{sig_structure_data, AsCborValue, SignatureContext};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Clone, Debug, Default)]
pub struct CoseSign1(pub(crate) coset::CoseSign1, Arc<Mutex<Option<i64>>>);

impl CoseSign1 {
    pub fn new(cose_sign1: coset::CoseSign1) -> Self {
        Self(cose_sign1, Arc::new(Mutex::new(None)))
    }
}

impl Serialize for CoseSign1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // todo: map_err
        self.0
            .clone()
            .to_cbor_value()
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CoseSign1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Deserialize the input to a CBOR Value
        let value = Value::deserialize(deserializer)?;

        // Convert the CBOR Value to CoseSign1
        let inner = coset::CoseSign1::from_cbor_value(value).map_err(serde::de::Error::custom)?;

        Ok(CoseSign1(inner, Arc::new(Mutex::new(None))))
    }
}

static mut SIGNATURE_PAYLOAD: OnceLock<HashMap<i64, Vec<u8>>> = OnceLock::new();
static ATOMIC_CTR: AtomicI64 = AtomicI64::new(0);

impl Cose for CoseSign1 {
    fn signature_payload(&self) -> &[u8] {
        // We need to return a reference to a value that is build in-place,
        // so we need to keep it somewhere. We use a global map for this.
        let payload = sig_structure_data(
            SignatureContext::CoseSign1,
            self.0.protected.clone(),
            None,
            &[],
            self.0.payload.as_ref().unwrap_or(&vec![]),
        );
        let mut guard = self.1.lock().unwrap();
        let id = guard.get_or_insert(ATOMIC_CTR.fetch_add(1, Ordering::SeqCst));
        unsafe {
            let map = SIGNATURE_PAYLOAD.get_or_init(HashMap::new);
            SIGNATURE_PAYLOAD.get_mut().unwrap().insert(*id, payload);
            map.get(id).unwrap()
        }
    }

    fn set_signature(&mut self, signature: Vec<u8>) {
        self.0.signature = signature;
    }
}

impl Drop for CoseSign1 {
    fn drop(&mut self) {
        // Remove the signature payload from the global map
        if let Some(id) = self.1.lock().unwrap().take() {
            unsafe {
                SIGNATURE_PAYLOAD.get_mut().unwrap().remove(&id);
            }
        }
    }
}

mod p256 {
    use crate::cose::SignatureAlgorithm;
    use coset::iana;
    use p256::ecdsa::{SigningKey, VerifyingKey};

    impl SignatureAlgorithm for SigningKey {
        fn algorithm(&self) -> iana::Algorithm {
            iana::Algorithm::ES256
        }
    }

    impl SignatureAlgorithm for VerifyingKey {
        fn algorithm(&self) -> iana::Algorithm {
            iana::Algorithm::ES256
        }
    }
}

mod p384 {
    use crate::cose::SignatureAlgorithm;
    use coset::iana;
    use p384::ecdsa::{SigningKey, VerifyingKey};

    impl SignatureAlgorithm for SigningKey {
        fn algorithm(&self) -> iana::Algorithm {
            iana::Algorithm::ES384
        }
    }

    impl SignatureAlgorithm for VerifyingKey {
        fn algorithm(&self) -> iana::Algorithm {
            iana::Algorithm::ES384
        }
    }
}

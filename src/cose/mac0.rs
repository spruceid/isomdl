use crate::cose::Cose;
use coset::cbor::Value;
use coset::{mac_structure_data, AsCborValue, MacContext};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Clone, Debug, Default)]
pub struct CoseMac0(pub(crate) coset::CoseMac0, Arc<Mutex<Option<i64>>>);

impl CoseMac0 {
    pub fn new(cose_mac0: coset::CoseMac0) -> Self {
        Self(cose_mac0, Arc::new(Mutex::new(None)))
    }
}

impl Serialize for CoseMac0 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // todo: map_err
        self.0
            .clone()
            .to_cbor_value()
            .unwrap()
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CoseMac0 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Deserialize the input to a CBOR Value
        let value = Value::deserialize(deserializer)?;

        // Convert the CBOR Value to CoseMac0
        let inner = coset::CoseMac0::from_cbor_value(value).map_err(serde::de::Error::custom)?;

        Ok(CoseMac0(inner, Arc::new(Mutex::new(None))))
    }
}

static mut SIGNATURE_PAYLOAD: OnceLock<HashMap<i64, Vec<u8>>> = OnceLock::new();
static ATOMIC_CTR: AtomicI64 = AtomicI64::new(0);

impl Cose for CoseMac0 {
    fn signature_payload(&self) -> &[u8] {
        // We need to return a reference to a value that is build in-place,
        // so we need to keep it somewhere. We use a global map for this.
        let payload = mac_structure_data(
            MacContext::CoseMac0,
            self.0.protected.clone(),
            &[],
            self.0.payload.as_ref().expect("payload missing"), // safe: documented
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
        self.0.tag = signature;
    }
}

impl Drop for CoseMac0 {
    fn drop(&mut self) {
        // Remove the signature payload from the global map
        if let Some(id) = self.1.lock().unwrap().take() {
            unsafe {
                SIGNATURE_PAYLOAD.get_mut().unwrap().remove(&id);
            }
        }
    }
}

mod hmac {
    use coset::iana;
    use hmac::Hmac;
    use sha2::{Sha256, Sha384, Sha512};

    use super::super::SignatureAlgorithm;

    /// Implement [`SignatureAlgorithm`] for each `HMAC` variant.

    impl SignatureAlgorithm for Hmac<Sha256> {
        fn algorithm(&self) -> iana::Algorithm {
            iana::Algorithm::HMAC_256_256
        }
    }

    impl SignatureAlgorithm for Hmac<Sha384> {
        fn algorithm(&self) -> iana::Algorithm {
            iana::Algorithm::HMAC_384_384
        }
    }

    impl SignatureAlgorithm for Hmac<Sha512> {
        fn algorithm(&self) -> iana::Algorithm {
            iana::Algorithm::HMAC_512_512
        }
    }
}

mod aes_cbc_mac {
    use super::super::SignatureAlgorithm;
    use aes::{Aes128, Aes256};
    use cbc_mac::CbcMac;
    use coset::iana;

    type Aes128CbcMac = CbcMac<Aes128>;
    type Aes256CbcMac = CbcMac<Aes256>;

    /// Implement [`SignatureAlgorithm`] for each `AES-CBC-MAC` variant.

    impl SignatureAlgorithm for Aes128CbcMac {
        fn algorithm(&self) -> iana::Algorithm {
            iana::Algorithm::AES_MAC_128_128
        }
    }

    impl SignatureAlgorithm for Aes256CbcMac {
        fn algorithm(&self) -> iana::Algorithm {
            iana::Algorithm::AES_MAC_256_128
        }
    }
}

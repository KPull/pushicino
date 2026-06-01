use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{AeadMut, Buffer, Nonce, OsRng};
use aes_gcm::{Aes128Gcm, Key, KeyInit};
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use hkdf::{Hkdf, InvalidLength};
use sha2::Sha256;

/// Encodes the given message using the given key, as a single record, in accordance with RFC 8188
/// This function will return the `EncryptedPayload` that can be put directly into the HTTP body.
pub(crate) fn encode(key: &impl EncodingKey, message: &[u8]) -> Result<EncryptedPayload, Error> {
    let plaintext_size = message.len();

    if plaintext_size > 3993 {
        return Err(Error::MessageTooLong);
    }

    const RS: u32 = 4096u32;
    let salt = Salt::random();
    let (keyid, ikm) = key.ikm().map_err(|e| Error::FailedToGenerateIkm)?;
    let idlen = keyid.0.len() as u8;

    let hkdf = Hkdf::<Sha256>::new(Some(&salt.0), &ikm.0);

    const CEK_INFO: &[u8] = b"Content-Encoding: aes128gcm\0";
    let mut cek = [0u8; 16];
    hkdf.expand(CEK_INFO, &mut cek)
        .map_err(|e| Error::InvalidCekLength(e))?;

    const NONCE_INFO: &[u8] = b"Content-Encoding: nonce\0";
    let mut nonce = [0u8; 12];
    hkdf.expand(NONCE_INFO, &mut nonce)
        .map_err(|e| Error::InvalidNonceLength(e))?;

    const FINAL_RECORD_DELIMITER: u8 = 0x02;
    let mut delimited_message = Vec::with_capacity(message.len() + 1);
    delimited_message.extend_from_slice(message);
    delimited_message.push(FINAL_RECORD_DELIMITER);

    // Note that we omit the exclusive-OR from the NONCE because we are only encoding a single
    // record and the sequence number of the first record is 0.

    let cek = Key::<Aes128Gcm>::from_slice(&cek);
    let nonce = Nonce::<Aes128Gcm>::from_slice(&nonce);
    let mut cipher = Aes128Gcm::new(&cek);
    let ciphertext = cipher
        .encrypt(&nonce, delimited_message.as_slice())
        .map_err(|e| Error::FailedToInitializeCipher(e))?;

    let header = ContentCodingHeader {
        salt,
        rs: RS,
        idlen,
        keyid: keyid.0.to_vec(),
    };

    Ok(EncryptedPayload {
        header,
        record: ciphertext,
    })
}

pub(crate) struct Keyid(pub [u8; 65]);
pub(crate) struct InputKeyingMaterial(pub [u8; 32]);

/// Implemented by structs that can be used to generate the Input Keying Material (IKM) for
/// generating the encoded data in accordance with RFC 8188
pub(crate) trait EncodingKey {
    type Error;

    /// Returns the Keyid and actual AES128GCM key data, known as the Input Keying
    /// Material (IKM) in RFC 8188, that will be used to encrypt the payload
    fn ikm(&self) -> Result<(Keyid, InputKeyingMaterial), Self::Error>;
}

struct ContentCodingHeader {
    /// The "salt" parameter comprises the first 16 octets of the
    /// "aes128gcm" content-coding header.  The same "salt" parameter
    ///  value MUST NOT be reused for two different payload bodies that
    ///  have the same input-keying material; generating a random salt for
    ///  every application of the content coding ensures that content-
    ///  encryption key reuse is highly unlikely.
    salt: Salt,

    /// The "rs" or record size parameter contains an unsigned 32-bit
    /// integer in network byte order that describes the record size in
    /// octets.  Note that it is, therefore, impossible to exceed the
    /// 2^36-31 limit on plaintext input to AEAD_AES_128_GCM.  Values
    /// smaller than 18 are invalid.
    rs: u32,

    /// The "idlen" parameter is an unsigned 8-bit integer that
    /// defines the length of the "keyid" parameter.
    idlen: u8,

    /// The "keyid" parameter can be used to identify the keying
    /// material that is used.  This field is the length determined by the
    /// "idlen" parameter.  Recipients that receive a message are expected
    /// to know how to retrieve keys; the "keyid" parameter might be input
    /// to that process. For our case, this will be the ECDH application
    /// server public key that was used in the ECDH key exchange process.
    keyid: Vec<u8>,
}

impl From<&ContentCodingHeader> for Vec<u8> {
    fn from(value: &ContentCodingHeader) -> Self {
        let mut buffer = Vec::new();

        buffer.extend_from_slice(&value.salt.0);
        buffer.extend_from_slice(&value.rs.to_be_bytes());
        buffer.push(value.idlen);
        buffer.extend_from_slice(&value.keyid);

        buffer
    }
}

/// The final encrypted payload in accordance with RFC8188, containing the content coding header
/// and the single encrypted record. This struct can be supplied directly in the body of
/// an HTTP request.
pub(crate) struct EncryptedPayload {
    header: ContentCodingHeader,
    record: Vec<u8>,
}

impl From<&EncryptedPayload> for Vec<u8> {
    fn from(value: &EncryptedPayload) -> Self {
        let header_bytes = Vec::<u8>::from(&value.header);
        let record_bytes = &value.record;

        let mut buffer = Vec::with_capacity(header_bytes.len() + record_bytes.len());

        buffer.extend_from_slice(&header_bytes);
        buffer.extend_from_slice(record_bytes);

        buffer
    }
}

/// A sequence of 16 octets generated by the application server and used during the key generation
/// process when sending a push message
#[derive(Debug, Clone, PartialEq, Eq)]
struct Salt([u8; 16]);

#[cfg(not(test))]
impl Salt {
    fn random() -> Self {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        Self(salt)
    }
}

#[cfg(test)]
impl Salt {
    fn random() -> Self {
        let salt: [u8; 16] = BASE64_URL_SAFE_NO_PAD
            .decode("DGv6ra1nlYgDCS1FRnbzlw")
            .unwrap()
            .try_into()
            .unwrap();
        Self(salt)
    }
}

#[derive(Debug)]
pub(crate) enum Error {
    MessageTooLong,
    FailedToGenerateIkm,
    InvalidCekLength(InvalidLength),
    InvalidNonceLength(InvalidLength),
    FailedToInitializeCipher(aes_gcm::Error),
}

#[cfg(test)]
mod tests {
    use crate::rfc8188::{encode, EncodingKey, InputKeyingMaterial, Keyid};
    use base64::prelude::BASE64_URL_SAFE_NO_PAD;
    use base64::Engine;

    struct TestKey;

    impl EncodingKey for TestKey {
        type Error = ();

        fn ikm(&self) -> Result<(Keyid, InputKeyingMaterial), Self::Error> {
            let application_server_public_key: [u8; 65] = BASE64_URL_SAFE_NO_PAD
                .decode(
                    "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIg\
                    Dll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8",
                )
                .unwrap()
                .try_into()
                .unwrap();

            let ikm: [u8; 32] = BASE64_URL_SAFE_NO_PAD
                .decode("S4lYMb_L0FxCeq0WhDx813KgSYqU26kOyzWUdsXYyrg")
                .unwrap()
                .try_into()
                .unwrap();

            let ikm = InputKeyingMaterial(ikm);

            Ok((Keyid(application_server_public_key), ikm))
        }
    }

    #[test]
    fn test_encode() {
        // Example from RFC 8291, Section 5.
        let result = encode(&TestKey, b"When I grow up, I want to be a watermelon");
        let payload = result.unwrap();
        let encoded_payload = BASE64_URL_SAFE_NO_PAD.encode::<Vec<u8>>((&payload).into());
        assert_eq!(encoded_payload, "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy\
        27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks\
        3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN")
    }
}

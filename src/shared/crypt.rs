/// unix timestamp
pub type Timestamp = i64;

pub use token::Token;
// ===== message signing =====
pub mod signing {
    use ed25519_compact::{KeyPair, PublicKey, SecretKey, Seed, Signature};

    /// ed25519 keypair
    pub fn gen_sign_keys() -> (SecretKey, PublicKey) {
        let kp = KeyPair::generate();
        (kp.sk, kp.pk)
    }

    /// deterministic keypair from 32-byte seed
    pub fn gen_sign_keys_from_seed(seed_bytes: [u8; 32]) -> (SecretKey, PublicKey) {
        let seed = Seed::new(seed_bytes);
        let kp = KeyPair::from_seed(seed);
        (kp.sk, kp.pk)
    }

    /// sign an arbitrary message with a SecretKey
    pub fn sign_message(sk: &SecretKey, msg: &[u8]) -> Signature {
        sk.sign(msg, None)
    }

    /// verify a signature with the matching PublicKey
    pub fn verify_signature(pk: &PublicKey, msg: &[u8], sig: &Signature) -> bool {
        pk.verify(msg, sig).is_ok()
    }
    // ===== tests =====
    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn sign_and_verify_roundtrip() {
            let (sk, pk) = gen_sign_keys();
            let message = b"hello world";

            let sig = sign_message(&sk, message);
            assert!(verify_signature(&pk, message, &sig));
        }

        #[test]
        fn verify_should_fail_with_wrong_key() {
            let (sk1, pk1) = gen_sign_keys();
            let (_, pk2) = gen_sign_keys();

            let message = b"attack at dawn";
            let sig = sign_message(&sk1, message);

            assert!(verify_signature(&pk1, message, &sig));
            assert!(!verify_signature(&pk2, message, &sig));
        }

        #[test]
        fn verify_should_fail_if_message_is_tampered() {
            let (sk, pk) = gen_sign_keys();
            let msg = b"original message";
            let mut sig = sign_message(&sk, msg);

            // corrupt message
            let tampered = b"tampered message";
            assert!(!verify_signature(&pk, tampered, &sig));

            // corrupt singwahruere
            sig[0] ^= 0xFF;
            assert!(!verify_signature(&pk, msg, &sig));
        }
    }
}

// ===== traffic encryption =====

pub mod traffic {
    use aes_gcm::{
        KeyInit, Nonce,
        aead::{Aead, OsRng, rand_core::RngCore},
    };
    use chacha20poly1305::ChaCha20Poly1305;
    use hkdf::Hkdf;
    use sha2::{Sha256, digest::typenum};
    use x25519_dalek::{PublicKey, StaticSecret};

    use crate::shared::crypt::token::DecryptError;
    /// make a good key out of anything (hkdf sha256)
    pub fn derive_key(secret: &str) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, secret.as_bytes());
        let mut okm = [0u8; 32];
        hk.expand(b"token-encryption", &mut okm).unwrap();
        okm
    }

    /// generates an ed25519 keypair
    pub fn gen_keys() -> (StaticSecret, PublicKey) {
        let secret = StaticSecret::random_from_rng(&mut OsRng);
        let public = PublicKey::from(&secret);
        (secret, public)
    }

    /// 32 byte aead key from raw dh shared secret w/ hkdf sha256
    pub fn hkdf_from_shared(shared: &[u8]) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, shared);
        let mut okm = [0u8; 32];
        hk.expand(b"lung/a0.1", &mut okm)
            .expect("this should never panic");
        okm
    }

    /// for the client to encrypt plaintext w/ a server's static pubkey
    /// out: [ephemeral_pub (32 bytes)] || [nonce (12 bytes)] || [ciphertext...]
    pub fn client_encrypt(server_pub: &PublicKey, plaintext: &[u8]) -> Vec<u8> {
        let eph_secret = StaticSecret::random_from_rng(&mut OsRng);
        let eph_pub = PublicKey::from(&eph_secret);

        let shared = eph_secret.diffie_hellman(server_pub);

        let aead_key_bytes = hkdf_from_shared(shared.as_bytes());

        // aead encrypt w/ 12 bit nonce chacha20poly1305
        let cipher = ChaCha20Poly1305::new(&aead_key_bytes.into());
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce: &Nonce<typenum::U12> = &nonce_bytes.into();

        let mut ciphertext = cipher
            .encrypt(nonce, plaintext)
            .expect("something went very wrong if this failed");

        // packs the whole thing
        let mut out = Vec::with_capacity(32 + 12 + ciphertext.len());
        out.extend(eph_pub.as_bytes());
        out.extend(&nonce_bytes);
        out.append(&mut ciphertext);
        out
    }

    pub fn server_decrypt(
        server_secret: &StaticSecret,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, DecryptError> {
        if ciphertext.len() < 32 + 12 {
            return Err(DecryptError::CiphertextTooShort);
        };
        let (eph_pub_bytes, rest) = ciphertext.split_at(32);
        let (nonce_bytes, ct) = rest.split_at(12);

        // this is the only way i can make the compiler be sure the array is 32 bytes
        let eph_pub_arr: [u8; 32] = eph_pub_bytes
            .try_into()
            .map_err(|_| DecryptError::InvalidPublicKey)?;
        let eph_pub = PublicKey::from(eph_pub_arr);

        let shared = server_secret.diffie_hellman(&eph_pub);
        let key_bytes = hkdf_from_shared(shared.as_bytes());

        let cipher = ChaCha20Poly1305::new(&key_bytes.into());
        let nonce = nonce_bytes.into();

        cipher
            .decrypt(nonce, ct)
            .map_err(|_| DecryptError::DecryptionFailed)
    }

    pub fn decrypt_aead(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, &'static str> {
        if data.len() < 12 {
            return Err("ciphertext too short");
        }
        let (nonce_bytes, ct) = data.split_at(12);
        let cipher = ChaCha20Poly1305::new(key.into());
        let nonce = nonce_bytes.into();
        cipher.decrypt(nonce, ct).map_err(|_| "decryption failed")
    }
    // ===== tests =====
    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn diffie_hellman_roundtrip_works() {
            let (server_secret, server_pub) = gen_keys();
            let (client_secret, client_pub) = gen_keys();

            let shared1 = client_secret.diffie_hellman(&server_pub);
            let shared2 = server_secret.diffie_hellman(&client_pub);

            assert_eq!(shared1.as_bytes(), shared2.as_bytes());
            assert_eq!(
                hkdf_from_shared(shared1.as_bytes()),
                hkdf_from_shared(shared2.as_bytes())
            );
        }

        #[test]
        fn client_can_encrypt_and_server_can_decrypt() {
            let (server_secret, server_pub) = gen_keys();
            let message = b"this is a top secret message";
            let ciphertext = client_encrypt(&server_pub, message);
            let plaintext = server_decrypt(&server_secret, &ciphertext).unwrap();
            assert_eq!(plaintext, message);
        }

        #[test]
        fn server_decrypt_fails_with_wrong_key() {
            let (_, server_pub) = gen_keys();
            let (wrong_secret, _) = gen_keys();

            let message = b"hello server";
            let ciphertext = client_encrypt(&server_pub, message);

            let result = server_decrypt(&wrong_secret, &ciphertext);
            assert!(matches!(result, Err(DecryptError::DecryptionFailed)));
        }

        #[test]
        fn server_decrypt_detects_tampered_ciphertext() {
            let (server_secret, server_pub) = gen_keys();
            let message = b"do not tamper";
            let mut ciphertext = client_encrypt(&server_pub, message);
            ciphertext[50] ^= 0xFF; // corrupt data
            let result = server_decrypt(&server_secret, &ciphertext);
            assert!(matches!(result, Err(DecryptError::DecryptionFailed)));
        }

        #[test]
        fn server_decrypt_fails_with_truncated_input() {
            let (server_secret, _) = gen_keys();
            let short = vec![0u8; 10];
            let result = server_decrypt(&server_secret, &short);
            assert!(matches!(result, Err(DecryptError::CiphertextTooShort)));
        }
    }
}

// ===== tokens =====

pub mod token {

    use chacha20poly1305::{
        ChaCha20Poly1305,
        aead::{Aead, AeadCore, KeyInit, OsRng},
    };

    use super::Timestamp;

    #[derive(Debug, Clone)]
    pub struct Token {
        id: String,
        until: Timestamp,
    }

    #[derive(Debug)]
    pub enum DecryptError {
        CiphertextTooShort,
        DecryptionFailed,
        InvalidUtf8,
        InvalidFormat,
        InvalidTimestamp,
        InvalidPublicKey,
    }

    impl Token {
        pub fn decrypt(ciphertext: Vec<u8>, key_bytes: &[u8; 32]) -> Result<Token, DecryptError> {
            if ciphertext.len() < 12 {
                return Err(DecryptError::CiphertextTooShort);
            }

            let key = key_bytes.into();
            let cipher = ChaCha20Poly1305::new(key);

            let (nonce_bytes, encrypted) = ciphertext.split_at(12);
            let nonce: [u8; 12] = nonce_bytes.try_into().unwrap();

            let plaintext = cipher
                .decrypt(&nonce.into(), encrypted)
                .map_err(|_| DecryptError::DecryptionFailed)?;

            let string = String::from_utf8(plaintext).map_err(|_| DecryptError::InvalidUtf8)?;
            let mut it = string.split_whitespace();

            // expected format: "id [id], until [timestamp]"
            if it.next() != Some("id") {
                return Err(DecryptError::InvalidFormat);
            }

            let id = it
                .next()
                .ok_or(DecryptError::InvalidFormat)?
                .trim_end_matches(',')
                .to_string();

            if it.next() != Some("until") {
                return Err(DecryptError::InvalidFormat);
            }

            let until_str = it.next().ok_or(DecryptError::InvalidFormat)?;
            let until = until_str
                .parse::<i64>()
                .map_err(|_| DecryptError::InvalidTimestamp)?;

            Ok(Self { id, until })
        }

        pub fn new(id: String, until: Timestamp) -> Token {
            Token { id, until }
        }

        pub fn encrypt(self, key_bytes: &[u8; 32]) -> Vec<u8> {
            let key = key_bytes.into();
            let cipher = ChaCha20Poly1305::new(key);
            let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
            let plaintext = format!("id {}, until {}", self.id, self.until);
            let mut ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).unwrap();

            let mut result = Vec::with_capacity(12 + ciphertext.len());
            result.extend_from_slice(&nonce);
            result.append(&mut ciphertext);

            result
        }
    }
    // ===== tests =====
    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::shared::crypt::traffic::derive_key;

        #[test]
        fn encrypt_and_decrypt_roundtrip() {
            let key = derive_key("supersecret");
            let original = Token::new("alice".into(), 12345);
            let ciphertext = original.clone().encrypt(&key);
            let decrypted = Token::decrypt(ciphertext, &key).unwrap();
            assert_eq!(original.id, decrypted.id);
            assert_eq!(original.until, decrypted.until);
        }

        #[test]
        fn decrypt_should_fail_with_wrong_key() {
            let key1 = derive_key("key1");
            let key2 = derive_key("key2");
            let tok = Token::new("bob".into(), 42);
            let ciphertext = tok.encrypt(&key1);
            assert!(Token::decrypt(ciphertext, &key2).is_err());
        }

        #[test]
        fn decrypt_should_fail_with_tampered_data() {
            let key = derive_key("yo");
            let tok = Token::new("eve".into(), 1337);
            let mut ciphertext = tok.encrypt(&key);
            ciphertext[15] ^= 0xAA;
            assert!(Token::decrypt(ciphertext, &key).is_err());
        }
    }
}

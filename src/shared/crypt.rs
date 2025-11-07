// task: encrypt all traffic during transit
//
// flow:
// client requests a pubkey on first use

use ed25519_compact::{KeyPair, Seed};

/// generates an ed25519 keypair
fn gen_keys() -> KeyPair {
    KeyPair::from_seed(Seed::default())
}

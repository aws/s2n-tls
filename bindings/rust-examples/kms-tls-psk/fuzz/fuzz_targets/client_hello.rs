#![no_main]

use kms_tls_psk::ClientHello;
use kms_tls_psk::DecodeValue;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ClientHello::decode_from(data);
});

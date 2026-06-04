//! Build a STUN Binding request with ICE attributes, `MESSAGE-INTEGRITY`, and
//! `FINGERPRINT`, then encode it and print a hex dump. Also decodes it back and
//! verifies the integrity, demonstrating the full round trip without any
//! network access.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example 01_binding_request
//! ```

use stun::{auth, Attribute, Class, Message, Method, TransactionId};

fn hex_dump(bytes: &[u8]) {
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        println!("{:04x}: {}", i * 16, hex.join(" "));
    }
}

fn main() {
    let password = "VOkJxbRl1RmTxUk/WvJxBt";
    let key = auth::short_term_key(password);

    let message = Message::builder(Method::Binding, Class::Request)
        .transaction_id(TransactionId::random())
        .attribute(Attribute::Software("doomfish-stun/0.1".to_owned()))
        .attribute(Attribute::Username("evtj:h6vY".to_owned()))
        .attribute(Attribute::Priority(0x6e00_01ff))
        .attribute(Attribute::IceControlling(0x932f_f9b1_5126_3b36))
        .with_message_integrity_sha1(&key)
        .with_fingerprint()
        .build();

    let bytes = message.encode();

    println!("Binding request ({} bytes):", bytes.len());
    hex_dump(&bytes);

    println!("\nMethod:  {:?}", message.method());
    println!("Class:   {:?}", message.class());
    println!("Tx ID:   {:02x?}", message.transaction_id().as_bytes());

    let decoded = Message::decode(&bytes).expect("decode");
    decoded
        .verify_message_integrity(&key)
        .expect("MESSAGE-INTEGRITY verifies");
    decoded.verify_fingerprint().expect("FINGERPRINT verifies");
    println!("\nDecoded round trip OK; integrity and fingerprint verified.");
}

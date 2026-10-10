fn main() {
    let result = hum_android_blst_probe::run_probe();
    assert!(
        result.valid_signature
            && result.altered_message_rejected
            && result.malformed_public_key_rejected
            && result.malformed_signature_rejected
    );
    assert_eq!((result.public_key_bytes, result.signature_bytes), (48, 96));
    println!("blst Android probe passed: {result:?}");
}

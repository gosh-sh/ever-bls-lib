// 2022-2024 (c) Copyright Contributors to the GOSH DAO. All rights reserved.
//
use gosh_bls_lib::bls::gen_bls_key_pair_based_on_key_material;
use gosh_bls_lib::bls::BLS_SECRET_KEY_LEN;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert!(args.len() > 1, "Secret key should be passed as an argument");

    let mut secret_key = [0_u8; BLS_SECRET_KEY_LEN];
    hex::decode_to_slice(args[1].trim_start_matches("0x"), &mut secret_key)
        .expect("Failed to decode secret key from hex");

    let (public, secret) = gen_bls_key_pair_based_on_key_material(&secret_key)
        .expect("Failed to generate BLS key pair");
    println!(
        r#"{{
  "public": "{}",
  "secret": "{}"
}}"#,
        hex::encode(public),
        hex::encode(secret)
    );
}

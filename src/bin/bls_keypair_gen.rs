// 2022-2024 (c) Copyright Contributors to the GOSH DAO. All rights reserved.
//
use gosh_bls_lib::bls::gen_bls_key_pair;
use gosh_bls_lib::bls::gen_bls_key_pair_based_on_key_material;
use gosh_bls_lib::bls::BLS_SECRET_KEY_LEN;
use clap::Parser;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// Hex string with 32 bytes of key material for bls
    #[arg(short, long)]
    key_material: Option<String>
}


fn main() {
    let args: Args = Args::parse();

    let (public, secret) = if let Some(key_material) = args.key_material {
        let mut secret_key = [0_u8; BLS_SECRET_KEY_LEN];
        hex::decode_to_slice(key_material.trim_start_matches("0x"), &mut secret_key)
            .expect("Failed to decode secret key from hex");

        gen_bls_key_pair_based_on_key_material(&secret_key)
            .expect("Failed to generate BLS key pair")
    } else {
        gen_bls_key_pair().expect("Failed to generate BLS key pair")
    };

    println!(
        r#"{{
  "public": "{}",
  "secret": "{}"
}}"#,
        hex::encode(public),
        hex::encode(secret)
    );
}

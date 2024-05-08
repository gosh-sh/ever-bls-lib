// 2022-2024 (c) Copyright Contributors to the GOSH DAO. All rights reserved.
//
use clap::Parser;
use gosh_bls_lib::bls::gen_bls_key_pair;
use gosh_bls_lib::bls::gen_bls_key_pair_based_on_key_material;
use gosh_bls_lib::bls::BLS_SECRET_KEY_LEN;
use gosh_bls_lib::serde_bls::BLSKeyPair;

const DEFAULT_FILE_STEM: &str = "bls_";
const FILE_EXTENSION: &str = ".keys.json";

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// Hex string with 32 bytes of key material
    #[arg(short, long)]
    key_material: Option<String>,
    /// Number of key pairs that should be generated
    #[arg(short, long)]
    number: Option<u32>,
    /// Output directory for generated keys (use only for generating several keys)
    #[arg(short, long, conflicts_with = "path", requires = "number")]
    output_dir: Option<String>,
    /// Output file path (use only for generating a single key)
    #[arg(short, long, conflicts_with_all = ["output_dir", "number"])]
    path: Option<String>,
    /// Output file stem (used to generate several files: <stem><i>.keys.json
    #[arg(long, conflicts_with = "path", requires = "number")]
    output_stem: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let args: Args = Args::parse();

    // Generate first key pair, that will be used as seed in case of generating several keys
    let first_key = BLSKeyPair::from(if let Some(key_material) = args.key_material {
        let mut secret_key = [0_u8; BLS_SECRET_KEY_LEN];
        hex::decode_to_slice(key_material.trim_start_matches("0x"), &mut secret_key)
            .map_err(|e| anyhow::format_err!("Failed to decode secret key from hex: {e}"))?;

        gen_bls_key_pair_based_on_key_material(&secret_key)
            .map_err(|e| anyhow::format_err!("Failed to generate BLS key pair: {e}"))?
    } else {
        gen_bls_key_pair()
            .map_err(|e| anyhow::format_err!("Failed to generate BLS key pair: {e}"))?
    });

    if let Some(path) = args.path {
        return first_key.save_to_file(path);
    }
    if let Some(number) = args.number {
        let file_stem = args.output_stem.unwrap_or(DEFAULT_FILE_STEM.to_string());
        let output_dir = args.output_dir.unwrap_or(".".to_string());
        if !std::path::Path::new(&output_dir).exists() {
            std::fs::create_dir_all(&output_dir)?;
        }
        let full_path_stem = format!("{}/{}", output_dir.trim_end_matches('/'), file_stem);

        let path = format!("{}{}{}", full_path_stem, 0, FILE_EXTENSION);
        first_key.save_to_file(path)?;

        let mut prev_key = first_key;
        for i in 1..number {
            let key_pair = BLSKeyPair::from(
                gen_bls_key_pair_based_on_key_material(&prev_key.secret)
                    .map_err(|e| anyhow::format_err!("Failed to generate BLS key pair: {e}"))?,
            );
            let path = format!("{}{}{}", full_path_stem, i, FILE_EXTENSION);
            key_pair.save_to_file(path)?;
            prev_key = key_pair;
        }
        return Ok(());
    }

    println!("{}", first_key.to_string()?);

    Ok(())
}

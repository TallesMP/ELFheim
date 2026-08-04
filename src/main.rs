mod license;

use std::error::Error;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand};
use rsa::RsaPrivateKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;

use license::License;

#[derive(Parser)]
#[command(name = "elfheim", version, about = "Protetor de binarios ELF (DRM)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    GenLicense(GenLicenseArgs),
}

#[derive(Args)]
struct GenLicenseArgs {
    #[arg(long)]
    private_key: PathBuf,
    #[arg(long)]
    user_id: u64,
    #[arg(long)]
    product_id: u32,
    #[arg(long, default_value_t = 30)]
    valid_days: u32,
    #[arg(long)]
    output: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::GenLicense(args) => gen_license(args),
    }
}

fn gen_license(args: GenLicenseArgs) -> Result<(), Box<dyn Error>> {
    let private_key = load_private_key(&args.private_key)?;
    let issued_at = now_unix()?;
    let expires_at = issued_at + i64::from(args.valid_days) * 86_400;
    let license = License {
        user_id: args.user_id,
        product_id: args.product_id,
        issued_at,
        expires_at,
    };
    let token = license.sign(private_key)?;
    match args.output {
        Some(path) => {
            std::fs::write(&path, format!("{token}\n"))?;
            eprintln!("license written in {}", path.display());
        }
        None => println!("{token}"),
    }
    Ok(())
}

fn now_unix() -> Result<i64, Box<dyn Error>> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64)
}

fn load_private_key(path: &Path) -> Result<RsaPrivateKey, Box<dyn Error>> {
    let pem = std::fs::read_to_string(path)?;
    RsaPrivateKey::from_pkcs8_pem(&pem)
        .or_else(|_| RsaPrivateKey::from_pkcs1_pem(&pem))
        .map_err(|err| format!("invalid RSA key: {err}").into())
}

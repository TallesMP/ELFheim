mod elf;
mod license;
mod payload;

use std::error::Error;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand};
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};

use license::License;
use payload::Payload;

#[derive(Parser)]
#[command(name = "elfheim", version, about = "Protetor de binarios ELF (DRM)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    GenLicense(GenLicenseArgs),
    Protect(ProtectArgs),
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

#[derive(Args)]
struct ProtectArgs {
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    public_key: PathBuf,
    #[arg(long)]
    license: PathBuf,
    #[arg(long)]
    output: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::GenLicense(args) => gen_license(args),
        Command::Protect(args) => protect(args),
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

fn protect(args: ProtectArgs) -> Result<(), Box<dyn Error>> {
    let binary = std::fs::read(&args.input)?;
    let public_key = load_public_key_der(&args.public_key)?;
    let license = read_license_token(&args.license)?;
    let payload = Payload {
        public_key,
        license: license.into_bytes(),
    }
    .serialize();
    let injection = elf::inject_note_as_load(binary, &payload)?;
    std::fs::write(&args.output, &injection.data)?;
    eprintln!("protected binary written in {}", args.output.display());
    eprintln!(
        "injected {} bytes at vaddr {:#x} (file offset {:#x})",
        injection.len, injection.vaddr, injection.offset
    );
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

fn load_public_key_der(path: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
    let pem = std::fs::read_to_string(path)?;
    let key = RsaPublicKey::from_public_key_pem(&pem)
        .or_else(|_| RsaPublicKey::from_pkcs1_pem(&pem))
        .map_err(|err| format!("invalid RSA public key: {err}"))?;
    let der = key.to_public_key_der()?;
    Ok(der.as_bytes().to_vec())
}

fn read_license_token(path: &Path) -> Result<String, Box<dyn Error>> {
    let text = std::fs::read_to_string(path)?;
    let token = text.trim();
    if token.is_empty() {
        return Err("license file is empty".into());
    }
    Ok(token.to_string())
}

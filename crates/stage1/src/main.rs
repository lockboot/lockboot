// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use vaportpm_attest::{Tpm, PcrOps};
use reqwest::blocking::Client;
use rustls::crypto::CryptoProvider;
use serde::{Deserialize, Serialize};
use serde::de::Error as _;
use sha2::{Digest, Sha256};
use vaportpm_attest as tpm;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const EC2_TOKEN_URL: &str = "http://169.254.169.254/latest/api/token";
const EC2_METADATA_URL: &str = "http://169.254.169.254/latest/user-data";
const GCP_METADATA_URL: &str = "http://metadata.google.internal/computeMetadata/v1/instance/attributes/user-data";
const AZURE_METADATA_URL: &str = "http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-02-01&format=text";
const TMP_DIR: &str = "/tmp";

const PCR_BINARY: u8 = 14;  // PCR 14: Stage2 binary hash
const PCR_CONFIG: u8 = 15;  // PCR 15: Configuration data hash

#[derive(Debug, Serialize, Deserialize)]
struct UserData {
    _stage2: Stage2Config,
}

#[derive(Debug, Serialize, Deserialize)]
struct Stage2Config {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    args: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    aarch64: Option<ArchConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    x86_64: Option<ArchConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ArchConfig {
    #[serde(deserialize_with = "deserialize_http_url")]
    url: String,
    #[serde(deserialize_with = "deserialize_sha256")]
    sha256: String,
}

fn main() {
    let result = main_inner();

    // Flush output before exiting (especially important when running as PID 1)
    let _ = io::stdout().flush();
    let _ = io::stderr().flush();

    // Handle errors explicitly to ensure stderr is flushed before exit
    if let Err(e) = result {
        eprintln!("Error: {:#}", e);
        let _ = io::stderr().flush();
        poweroff();
    }
}

fn main_inner() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    // This runs when: PID is 1 (init process) OR no arguments provided
    if is_pid1() || args.len() <= 1 {
        return stage2(fetch_cloud_metadata()?);
    }
    // Handle --attest command
    if args[1] == "--attest" {
        let nonce = if args.len() > 2 {
            args[2].as_bytes().to_vec()
        } else {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("System time before UNIX epoch")
                .as_secs()
                .to_string()
                .into_bytes()
        };
        return Ok(println!("{}", tpm::attest(&nonce)?));
    }
    // Handle --make-config command
    if args[1] == "--make-config" {
        if args.len() < 4 || args.len() > 5 {
            return Err(anyhow!("Usage: stage1 --make-config <aarch64|x86_64> <URL> [config.json]"));
        }
        let arch = &args[2];
        if arch != "aarch64" && arch != "x86_64" {
            return Err(anyhow!("Architecture must be either 'aarch64' or 'x86_64'"));
        }
        return make_config(arch, &args[3], args.get(4).map(|s| s.as_str()));
    }
    // Handle other arguments (--url, --file)
    if args.len() == 3 {
        return stage2(
            parse_json_to_config(
                match args[1].as_str() {
                    "--url" => fetch_from_url(&args[2])?,
                    "--file" => read_from_file(&args[2])?,
                    _ => return Err(anyhow!("Invalid argument. Use --url <URL> or --file <PATH>"))
        })?);
    }
    Err(anyhow!(
        "Usage: stage1 [--url <URL> | --file <PATH> | --make-config <ARCH> <URL> [config.json] | --attest]\n\
         If no arguments are provided (or pid==1): fetches from EC2 metadata service.\n\
         --make-config: Download a file, compute SHA256, and output a JSON config with _stage2.<ARCH>\n\
                        ARCH must be 'aarch64' or 'x86_64'. Can be run multiple times with different\n\
                        architectures and the same config.json to build a multi-arch config.\n\
         --attest: Generate TPM attestation with EK certificates, PCRs, and certified signing key"
    ))
}

/// Get kernel-style timestamp string: [    2.231397]
/// Uses clock_gettime with CLOCK_BOOTTIME for accurate system uptime
fn kts() -> String {
    unsafe {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // CLOCK_BOOTTIME = time since boot including suspend time
        if libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) == 0 {
            let secs = ts.tv_sec as u64;
            let micros = (ts.tv_nsec / 1000) as u32;
            return format!("[{:>5}.{:06}]", secs, micros);
        }
    }
    // Fallback if clock_gettime fails
    "[    ?.??????]".to_string()
}

/// Macro for eprintln with kernel-style timestamp
macro_rules! ktseprintln {
    ($($arg:tt)*) => {
        eprintln!("{} stage1: {}", kts(), format_args!($($arg)*))
    };
}

/// Compute SHA256 hash of one or more byte slices
macro_rules! sha256 {
    ($($item:expr),+ $(,)?) => {{
        let mut hasher = Sha256::new();
        $(hasher.update($item);)+
        <[u8; 32]>::from(hasher.finalize())
    }};
}

/// Check if running as root (UID == 0)
fn is_root() -> bool {
    unsafe { libc::getuid() == 0 }
}

fn is_pid1() -> bool {
    std::process::id() == 1
}

/// Get the appropriate architecture config based on the target architecture
fn get_arch_config(stage2: &Stage2Config) -> Result<&ArchConfig> {
    #[cfg(target_arch = "aarch64")]
    let arch_config = stage2.aarch64.as_ref();

    #[cfg(target_arch = "x86_64")]
    let arch_config = stage2.x86_64.as_ref();

    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    let arch_config: Option<&ArchConfig> = None;

    arch_config.ok_or_else(|| {
        #[cfg(target_arch = "aarch64")]
        return anyhow!("No aarch64 configuration found in _stage2");

        #[cfg(target_arch = "x86_64")]
        return anyhow!("No x86_64 configuration found in _stage2");

        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        return anyhow!("Unsupported architecture");
    })
}

fn poweroff() {
    if is_pid1() {
        unsafe {
            libc::sync();
            thread::sleep(Duration::from_secs(60));
            libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
        }
    } else {
        std::process::exit(1);
    }
}

fn deserialize_http_url<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).and_then(|s| {
        if !s.starts_with("http://") && !s.starts_with("https://") {
            Err(D::Error::custom("url must start with http:// or https://"))
        } else if !s.chars().all(|c| c.is_ascii_graphic()) {
            Err(D::Error::custom("url must contain only printable ASCII characters (no spaces, tabs, newlines, or control characters)"))
        } else {
            Ok(s)
        }
    })
}

fn deserialize_sha256<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).and_then(|s| match s.len() {
        64 if s.chars().all(|c| c.is_ascii_hexdigit()) => Ok(s),
        64 => Err(D::Error::custom("sha256 must contain only hexadecimal characters")),
        _ => Err(D::Error::custom("sha256 must be exactly 64 characters")),
    })
}

struct ParsedData {
    config: UserData,
    raw_json: Vec<u8>,
}

fn parse_json_to_config(data: Vec<u8>) -> Result<ParsedData> {
    Ok(ParsedData {
        config: serde_json::from_slice(&data).context("Failed to parse JSON")?,
        raw_json: data,
    })
}

fn make_config(arch: &str, url: &str, config_file: Option<&str>) -> Result<()> {
    let binary_data = download_binary(url)?;
    let sha256_hash = hex::encode(sha256!(binary_data));

    let arch_config = ArchConfig {
        url: url.to_string(),
        sha256: sha256_hash,
    };

    // Read existing config if provided, otherwise start with empty object
    let mut config: serde_json::Value = if let Some(path) = config_file {
        let contents = fs::read_to_string(path)
            .context(format!("Failed to read config file: {}", path))?;
        serde_json::from_str(&contents)
            .context("Failed to parse config JSON")?
    } else {
        serde_json::json!({})
    };

    // Ensure _stage2 exists
    if !config.is_object() {
        return Err(anyhow!("Config file must contain a JSON object"));
    }

    let config_obj = config.as_object_mut().unwrap();

    // Get or create _stage2 object
    let stage2_value = config_obj
        .entry("_stage2")
        .or_insert_with(|| serde_json::json!({}));

    if !stage2_value.is_object() {
        return Err(anyhow!("_stage2 must be a JSON object"));
    }

    // Add the architecture-specific config
    let stage2_obj = stage2_value.as_object_mut().unwrap();
    stage2_obj.insert(arch.to_string(), serde_json::to_value(arch_config)?);

    println!("{}", serde_json::to_string_pretty(&config)?);
    Ok(())
}

/// Generate attestation before modifying PCRs
/// extra_data = H(H(binary),H(config))
fn generate_pre_execution_attestation(binary_data: &[u8], config_json: &[u8]) -> Result<()> {
    let path = format!("{}/stage1.attest", TMP_DIR);
    let contents = tpm::attest(&sha256!(sha256!(config_json), sha256!(binary_data)))?;
    fs::write(&path, contents).context(format!("Failed to write attestation to {}", &path))?;
    Ok(())
}

/// Extend PCRs with binary and config data if running as root
/// PCR 14 is extended with the SHA256 hash of the stage2 binary
/// PCR 15 is extended with the SHA256 hash of the config JSON
fn extend_pcrs(binary_data: &[u8], config_json: &[u8]) -> Result<()> {
    let mut tpm = Tpm::open()?;
    tpm.pcr_extend(PCR_BINARY, &sha256!(binary_data))?;
    tpm.pcr_extend(PCR_CONFIG, &sha256!(config_json))?;
    Ok(())
}

fn stage2(parsed: ParsedData) -> Result<()> {
    let arch_config = get_arch_config(&parsed.config._stage2)?;
    let binary_data = download_binary(&arch_config.url)?;
    verify_checksum(&binary_data, &arch_config.sha256)?;
    if is_root() {
        generate_pre_execution_attestation(&binary_data, &parsed.raw_json)?;
        extend_pcrs(&binary_data, &parsed.raw_json)?;
    }
    let args = parsed.config._stage2.args.as_deref().unwrap_or(&[]);
    execute_binary(&binary_data, args, &parsed.raw_json)?;
    Ok(())
}

fn log_hash(label: &str, data: &[u8]) {
    ktseprintln!("{} sha256={}", label, hex::encode(sha256!(data)));
}

fn http_client() -> Result<Client> {
    // Install rustls-rustcrypto as the default crypto provider (only needs to be done once)
    let _ = CryptoProvider::install_default(rustls_rustcrypto::provider());
    Client::builder()
        .use_rustls_tls()
        .build()
        .context("Failed to build HTTP client")
}

/// Try to fetch user-data from AWS EC2 IMDSv2
fn try_fetch_ec2(client: &Client) -> Result<ParsedData> {
    // IMDSv2: First, obtain a session token
    let token = client
        .put(EC2_TOKEN_URL)
        .header("X-aws-ec2-metadata-token-ttl-seconds", "21600") // 6 hours
        .send()
        .context("Failed to obtain IMDSv2 session token")?
        .text()
        .context("Failed to read IMDSv2 token response")?;
    // IMDSv2: Use the token to fetch user-data
    let body = client
        .get(EC2_METADATA_URL)
        .header("X-aws-ec2-metadata-token", &token)
        .send()
        .context("Failed to fetch EC2 user-data")?
        .bytes()
        .context("Failed to read EC2 user-data response")?
        .to_vec();
    log_hash(EC2_METADATA_URL, &body);
    Ok(parse_json_to_config(body)?)
}

/// Try to fetch user-data from GCP metadata service
/// See: https://cloud.google.com/compute/docs/storing-retrieving-metadata
fn try_fetch_gcp(client: &Client) -> Result<ParsedData> {
    let body = client
        .get(GCP_METADATA_URL)
        .header("Metadata-Flavor", "Google")
        .send()
        .context("Failed to fetch GCP user-data")?
        .bytes()
        .context("Failed to read GCP user-data response")?
        .to_vec();
    log_hash(GCP_METADATA_URL, &body);
    Ok(parse_json_to_config(body)?)
}

/// Try to fetch user-data from Azure IMDS
/// See: https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service?tabs=linux#get-user-data
/// See: https://learn.microsoft.com/en-us/azure/virtual-machines/user-data
fn try_fetch_azure(client: &Client) -> Result<ParsedData> {
    let body = client
        .get(AZURE_METADATA_URL)
        .header("Metadata", "true")
        .send()
        .context("Failed to fetch Azure user-data")?
        .text()
        .context("Failed to read Azure user-data response")?;
    // Azure returns base64-encoded data, so decode it
    let decoded = STANDARD
        .decode(&body)
        .context("Failed to decode base64-encoded Azure user-data")?;
    log_hash(AZURE_METADATA_URL, &decoded);
    let parsed = parse_json_to_config(decoded)?;
    Ok(parsed)
}

/// Try to fetch metadata from all cloud providers
fn fetch_cloud_metadata() -> Result<ParsedData> {
    let client = http_client()?;
    try_fetch_ec2(&client)
        .or_else(|_| try_fetch_gcp(&client))
        .or_else(|_| try_fetch_azure(&client))
        .context("Failed to fetch metadata from any cloud provider (tried EC2, GCP, Azure)")
}

fn fetch_from_url(url: &str) -> Result<Vec<u8>> {
    let body = http_client()?
        .get(url)
        .send()
        .context("Failed to fetch user-data from URL")?
        .bytes()
        .context("Failed to read response from URL")?
        .to_vec();
    log_hash(url, &body);
    Ok(body)
}

fn read_from_file(path: &str) -> Result<Vec<u8>> {
    let data = fs::read(path)
        .context(format!("Failed to read file: {}", path))?;
    log_hash(path, data.as_slice());
    Ok(data)
}

fn download_binary(url: &str) -> Result<Vec<u8>> {
    let client = http_client()?;
    let binary_data = client
        .get(url)
        .send()
        .context("Failed to download binary")?
        .bytes()
        .context("Failed to read binary data")?
        .to_vec();
    log_hash(url, binary_data.as_slice());
    Ok(binary_data)
}

fn verify_checksum(data: &[u8], expected_hex: &str) -> Result<()> {
    let actual_hex = hex::encode(sha256!(data));
    if actual_hex.to_lowercase() != expected_hex.to_lowercase() {
        return Err(anyhow!(
            "SHA256 checksum mismatch!\nExpected: {}\nActual:   {}",
            expected_hex, actual_hex));
    }
    Ok(())
}

fn execute_binary(data: &[u8], args: &[String], json_config: &[u8]) -> Result<()> {
    let tmp_path = format!("{}/stage2.exe", TMP_DIR);    
    fs::write(&tmp_path, data)
        .context(format!("Failed to write binary to {}", tmp_path))?;

    // Make the binary executable
    let mut perms = fs::metadata(&tmp_path)
        .context("Failed to get file metadata")?
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&tmp_path, perms)
        .context("Failed to set executable permissions")?;

    let json_path = format!("{}/stage2-config.json", TMP_DIR);
    fs::write(&json_path, json_config)
        .context(format!("Failed to write config to {}", json_path))?;

    ktseprintln!("{}: {:?}\n", tmp_path, args);

    let err = Command::new(&tmp_path)
        .args(args)
        .exec();
    Err(anyhow!("Failed to exec binary: {}", err))
}

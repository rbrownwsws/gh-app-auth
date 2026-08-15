use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use reqwest::blocking::Client;
use reqwest::header;
use serde::{Deserialize, Serialize};

const DEFAULT_USER_AGENT: &str = "rbrownwsws/gh-app-auth";

const GITHUB_API_URL: &str = "https://api.github.com";

const MIME_GITHUB_API_JSON: &str = "application/vnd.github+json";

const HEADER_GITHUB_API_VERSION: &str = "X-GitHub-Api-Version";
const GITHUB_API_VERSION: &str = "2026-03-10";

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Gets information about App Installations
    GetInstallations(GetInstallationsArgs),

    /// Create an Installation Access Token
    CreateInstallationAccessToken(CreateInstallationAccessTokenArgs),
}

#[derive(Args)]
struct AppCredentialsArgs {
    /// The App's Client ID (or App ID)
    #[arg(short = 'c', long = "client-id", visible_alias = "app-id", env = "GHAA_CLIENT_ID")]
    client_id: String,

    /// Path to the App's private key file (PEM format)
    #[arg(short = 'k', long, env = "GHAA_PRIVATE_KEY_FILE")]
    private_key_file: PathBuf,
}

#[derive(Args)]
struct GetInstallationsArgs {
    #[command(flatten)]
    credentials: AppCredentialsArgs,
}

#[derive(Args)]
struct CreateInstallationAccessTokenArgs {
    #[command(flatten)]
    credentials: AppCredentialsArgs,

    #[arg(short = 'i', long, env = "GHAA_INSTALLATION_ID")]
    installation_id: u64,

    #[arg(short = 'o', long, env = "GHAA_OUT_FILE")]
    out_file: PathBuf,
}

#[derive(Debug, Serialize)]
struct Claims {
    iat: usize,
    exp: usize,
    iss: String,
}

struct JWT(String);

fn create_app_jwt(client_id: &str, key: &[u8]) -> anyhow::Result<JWT> {
    let header = Header::new(Algorithm::RS256);

    let now_timestamp_s = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as usize;

    // Claim issued in past to account for clock drift
    let iat = now_timestamp_s - 60;

    // Claim expires in 10 minutes (max allowed by GitHub)
    let exp = iat + (60 * 10);

    let token = encode(
        &header,
        &Claims {
            iat,
            exp,
            iss: client_id.to_owned(),
        },
        &EncodingKey::from_rsa_pem(key)?,
    )?;

    Ok(JWT(token))
}

fn create_client(jwt: &JWT) -> anyhow::Result<Client> {
    let mut headers = header::HeaderMap::new();

    headers.insert(header::USER_AGENT, DEFAULT_USER_AGENT.parse()?);

    let mut auth_value = header::HeaderValue::try_from(format!("Bearer {}", jwt.0))?;
    auth_value.set_sensitive(true);
    headers.insert(header::AUTHORIZATION, auth_value);

    headers.insert(HEADER_GITHUB_API_VERSION, GITHUB_API_VERSION.parse()?);
    headers.insert(header::ACCEPT, MIME_GITHUB_API_JSON.parse()?);

    let client = Client::builder().default_headers(headers).build()?;

    Ok(client)
}

#[derive(Clone, Debug, Deserialize)]
struct GHAccount {
    id: u64,
    login: String,
}

#[derive(Clone, Debug, Deserialize)]
struct GHAppInstallation {
    id: u64,

    account: GHAccount,
}

#[derive(Clone, Debug, Deserialize)]
struct GHAppInstallationTokenResponse {
    token: String,
}

fn create_client_from_args(creds: AppCredentialsArgs) -> anyhow::Result<Client> {
    let key_bytes = fs::read(&creds.private_key_file)?;

    let jwt = create_app_jwt(&creds.client_id, &key_bytes)?;

    let client = create_client(&jwt)?;

    Ok(client)
}

fn cmd_get_installations(args: GetInstallationsArgs) -> anyhow::Result<()> {
    let client = create_client_from_args(args.credentials)?;

    let response: Vec<GHAppInstallation> = client
        .get(format!("{GITHUB_API_URL}/app/installations"))
        .send()?
        .json()?;

    for install in response {
        println!(
            "{} - {} ({})",
            install.id, install.account.login, install.account.id
        )
    }

    Ok(())
}

fn cmd_create_installation_access_token(
    args: CreateInstallationAccessTokenArgs,
) -> anyhow::Result<()> {
    let client = create_client_from_args(args.credentials)?;

    let installation_id = args.installation_id;

    let response: GHAppInstallationTokenResponse = client
        .post(format!(
            "{GITHUB_API_URL}/app/installations/{installation_id}/access_tokens"
        ))
        .send()?
        .json()?;

    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(args.out_file)?;

    file.write_all(response.token.as_bytes())?;
    file.sync_all()?;

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::GetInstallations(args) => {
            cmd_get_installations(args)?;
        }

        Commands::CreateInstallationAccessToken(args) => {
            cmd_create_installation_access_token(args)?;
        }
    }

    Ok(())
}

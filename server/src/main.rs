use std::io::Read;
use std::sync::Arc;
use std::{env, fs};

use async_mutex::Mutex;
use cached::stores::TimedCache;
use slog::o;
use slog::Drain;
use sqlx::postgres::PgPoolOptions;

mod crypto;
mod logging;
mod models;
mod service;
mod slack;
mod utils;

pub type Error = Box<dyn std::error::Error>;

#[derive(Debug)]
struct StringError(String);
impl std::fmt::Display for StringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "error: {}", self.0)
    }
}
impl std::error::Error for StringError {}

pub type Result<T> = std::result::Result<T, Error>;

fn env_or(k: &str, default: &str) -> String {
    env::var(k).unwrap_or_else(|_| default.to_string())
}

lazy_static::lazy_static! {
    pub static ref CONFIG: Config = Config::load();

    // The "base" logger that all crates should branch off of
    pub static ref BASE_LOG: slog::Logger = {
        let level: slog::Level = CONFIG.log_level
                .parse()
                .expect("invalid log_level");
        if CONFIG.log_format == "pretty" {
            let decorator = slog_term::TermDecorator::new().build();
            let drain = slog_term::CompactFormat::new(decorator).build().fuse();
            let drain = slog_async::Async::new(drain).build().fuse();
            let drain = slog::LevelFilter::new(drain, level).fuse();
            slog::Logger::root(drain, o!())
        } else {
            let drain = slog_json::Json::default(std::io::stderr()).fuse();
            let drain = slog_async::Async::new(drain).build().fuse();
            let drain = slog::LevelFilter::new(drain, level).fuse();
            slog::Logger::root(drain, o!())
        }
    };

    // Base logger
    pub static ref LOG: slog::Logger = BASE_LOG.new(slog::o!("app" => "soundlog"));

    // state cache
    pub static ref ONE_TIME_TOKENS: Arc<Mutex<TimedCache<String, ()>>> = Arc::new(Mutex::new(TimedCache::with_lifespan(30)));
}

// build a string error
#[macro_export]
macro_rules! se {
    ($($arg:tt)*) => {{ crate::StringError(format!($($arg)*))}};
}

#[macro_export]
macro_rules! resp {
    (json => $obj:expr) => {{
        tide::Response::builder(200)
            .content_type("application/json")
            .body(serde_json::to_string(&$obj)?)
            .build()
    }};
    (status => $status:expr) => {{
        tide::Response::builder($status)
            .content_type("text/plain")
            .build()
    }};
    (status => $status:expr, message => $msg:expr) => {{
        tide::Response::builder($status)
            .content_type("text/plain")
            .body($msg)
            .build()
    }};
}

#[derive(serde::Deserialize)]
pub struct Config {
    pub version: String,

    // whether to listen on https or http
    pub ssl: bool,

    // host to listen on, defaults to localhost
    pub host: String,
    pub port: u16,

    // the "real" hostname (https://slackat.com) and domain slackat.com
    // used for building redirects
    pub real_hostname: Option<String>,
    pub real_domain: Option<String>,

    // json or pretty
    pub log_format: String,
    pub log_level: String,

    // db config
    pub db_url: String,
    pub db_max_connections: u32,

    // key used for encrypting slack auth tokens and things
    // saved in the db
    pub encryption_key: String,

    // -- The following are workarounds to deal with slack not
    // -- letting you specify two different login redirect hosts
    // -- despite the docs and examples making it look like you can.
    // an explicit slack auth login redirect to send to slack
    // on login requests instead of building one from this server's "real host"
    pub slack_auth_login_redirect: Option<String>,
    // these two keys are intended to be shared between dev environments
    // and the "prod" deployed environment. These are used to encrypt
    // and sign the slack auth redirect data which the prod env needs to
    // be able to decrypt and verify in order to redirect login requests
    // to dev environments.
    // -- key used for encrypting data sent in the slack login token
    pub slack_auth_encryption_key: String,
    // -- key used for signing the one-time-token sent to slack
    pub slack_auth_signing_key: String,

    // key used for generating auth tokens
    pub signing_key: String,
    pub auth_expiration_seconds: u32,

    // slack secrets
    pub slack_client_id: String,
    pub slack_secret_id: String,
}
impl Config {
    pub fn load() -> Self {
        let version = fs::File::open("commit_hash.txt")
            .map(|mut f| {
                let mut s = String::new();
                f.read_to_string(&mut s).expect("Error reading commit_hasg");
                s
            })
            .unwrap_or_else(|_| "unknown".to_string());
        Self {
            version,
            ssl: env_or("SSL", "false") == "true",
            host: env_or("HOST", "localhost"),
            port: env_or("PORT", "3030").parse().expect("invalid port"),
            real_hostname: env::var("REAL_HOSTNAME").ok(),
            real_domain: env::var("REAL_DOMAIN").ok(),
            log_format: env_or("LOG_FORMAT", "json")
                .to_lowercase()
                .trim()
                .to_string(),
            log_level: env_or("LOG_LEVEL", "INFO"),
            db_url: env_or("DATABASE_URL", "error"),
            db_max_connections: env_or("DATABASE_MAX_CONNECTIONS", "5")
                .parse()
                .expect("invalid DATABASE_MAX_CONNECTIONS"),
            // 60 * 24 * 30
            auth_expiration_seconds: env_or("AUTH_EXPIRATION_SECONDS", "43200")
                .parse()
                .expect("invalid auth_expiration_seconds"),
            slack_client_id: env_or("SLACK_CLIENT_ID", "fake"),
            slack_secret_id: env_or("SLACK_SECRET_ID", "fake"),
            encryption_key: env_or("ENCRYPTION_KEY", "01234567890123456789012345678901"),
            slack_auth_login_redirect: env::var("SLACK_AUTH_LOGIN_REDIRECT").ok(),
            slack_auth_encryption_key: env_or(
                "SLACK_AUTH_ENCRYPTION_KEY",
                "01234567890123456789012345678901",
            ),
            slack_auth_signing_key: env_or(
                "SLACK_AUTH_SIGNING_KEY",
                "01234567890123456789012345678901",
            ),
            signing_key: env_or("SIGNING_KEY", "01234567890123456789012345678901"),
        }
    }
    pub fn initialize(&self) {
        slog::info!(
            LOG, "initialized config";
            "version" => &CONFIG.version,
            "ssl" => &CONFIG.ssl,
            "host" => &CONFIG.host,
            "real_hostname" => &CONFIG.real_hostname,
            "real_domain" => &CONFIG.real_domain,
            "db_max_connections" => &CONFIG.db_max_connections,
            "port" => &CONFIG.port,
            "log_format" => &CONFIG.log_format,
            "log_level" => &CONFIG.log_level,
            "auth_expiration_seconds" => &CONFIG.auth_expiration_seconds,
        );
    }
    pub fn host(&self) -> String {
        let p = if self.ssl { "https" } else { "http" };
        format!("{}://{}:{}", p, self.host, self.port)
    }
    pub fn real_host(&self) -> String {
        self.real_hostname.clone().unwrap_or_else(|| self.host())
    }
    pub fn login_url(&self) -> String {
        format!("{}/login", self.real_host())
    }
    pub fn slack_redirect_url(&self) -> String {
        self.slack_auth_login_redirect
            .clone()
            .unwrap_or_else(|| format!("{}/login/slack", self.real_host()))
    }
    pub fn slack_redirect_proxy_url(&self) -> String {
        format!("{}/login/slack", self.real_host())
    }
    pub fn domain(&self) -> String {
        self.real_domain
            .clone()
            .unwrap_or_else(|| self.host.clone())
    }
}

#[async_std::main]
async fn main() -> Result<()> {
    // try sourcing a .env and server/.env if either exist
    dotenv::dotenv().ok();
    dotenv::from_path(
        std::env::current_dir()
            .map(|p| p.join("server/.env"))
            .unwrap(),
    )
    .ok();
    CONFIG.initialize();

    let pool = PgPoolOptions::new()
        .max_connections(CONFIG.db_max_connections)
        .connect(&CONFIG.db_url)
        .await?;
    service::start(pool.clone()).await?;
    Ok(())
}

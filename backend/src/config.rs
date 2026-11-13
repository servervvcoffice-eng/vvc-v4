use std::{env, net::SocketAddr};

pub const ALLOWED_ORIGIN: &str = "https://vvc-office.pages.dev";
const DEV_PASSWORD_PLACEHOLDER: &str = "ChangeMeNow!42";

#[derive(Clone, Debug)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub app_env: String,
    pub database_url: Option<String>,
    pub redis_url: Option<String>,
    pub bootstrap_email: Option<String>,
    pub session_idle_secs: u64,
    pub session_absolute_secs: u64,
    pub max_body_bytes: usize,
    pub gateway_secret: Option<String>,
    pub dev_password: String,
    pub cookie_secure: bool,
    /// Extra CORS origins (comma-separated `ALLOWED_ORIGINS`), in addition
    /// to `ALLOWED_ORIGIN`. The proxy flow is same-origin, so this list
    /// should stay short and contain only origins we actually serve.
    pub allowed_origins: Vec<String>,
    /// How long operational logs (views/activity/failed logins/spam) are
    /// kept before the retention job deletes them, in days.
    pub log_retention_days: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let port = parse_env("PORT", 3000_u16, 1..=65535)?;
        let app_env = env::var("APP_ENV").unwrap_or_else(|_| "development".into());
        let config = Self {
            bind_addr: SocketAddr::from(([0, 0, 0, 0], port)),
            app_env,
            database_url: non_empty("DATABASE_URL"),
            redis_url: non_empty("REDIS_URL"),
            bootstrap_email: non_empty("VVC_BOOTSTRAP_EMAIL"),
            session_idle_secs: parse_env("SESSION_IDLE_SECS", 1800_u64, 60..=86_400)?,
            session_absolute_secs: parse_env("SESSION_ABSOLUTE_SECS", 28_800_u64, 300..=604_800)?,
            max_body_bytes: parse_env("MAX_BODY_BYTES", 1_048_576_usize, 1_024..=16_777_216)?,
            gateway_secret: non_empty("VVC_GATEWAY_SECRET"),
            dev_password: env::var("VVC_DEV_PASSWORD").unwrap_or_default(),
            cookie_secure: env::var("COOKIE_SECURE")
                .map(|v| !v.eq_ignore_ascii_case("false"))
                .unwrap_or(true),
            allowed_origins: env::var("ALLOWED_ORIGINS")
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(str::to_string)
                .collect(),
            log_retention_days: parse_env("LOG_RETENTION_DAYS", 90_u64, 7..=3650)?,
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        // Fail closed on the gateway for every deployed environment, not
        // just production: a public Render origin with no gateway secret
        // lets anyone bypass the edge layer entirely. Local development
        // (`APP_ENV=development`, the default) is the only exception.
        if !self.app_env.eq_ignore_ascii_case("development") && self.gateway_secret.is_none() {
            return Err(ConfigError(
                "VVC_GATEWAY_SECRET is required outside local development".into(),
            ));
        }
        if self.app_env.eq_ignore_ascii_case("production") {
            if self.dev_password.is_empty() || self.dev_password == DEV_PASSWORD_PLACEHOLDER {
                return Err(ConfigError(
                    "VVC_DEV_PASSWORD must be set to a non-placeholder secret in production".into(),
                ));
            }
            if self.database_url.is_none() {
                return Err(ConfigError("DATABASE_URL is required in production".into()));
            }
            if self.redis_url.is_none() {
                return Err(ConfigError("REDIS_URL is required in production".into()));
            }
            if self.gateway_secret.is_none() {
                return Err(ConfigError(
                    "VVC_GATEWAY_SECRET is required in production".into(),
                ));
            }
            if self.bootstrap_email.is_none() {
                return Err(ConfigError(
                    "VVC_BOOTSTRAP_EMAIL is required for one-time production bootstrap".into(),
                ));
            }
            if !self.cookie_secure {
                return Err(ConfigError(
                    "COOKIE_SECURE must be true in production".into(),
                ));
            }
        } else if self.dev_password.is_empty() {
            return Err(ConfigError(
                "VVC_DEV_PASSWORD must be set for non-production local bootstrap".into(),
            ));
        }
        Ok(())
    }

    pub fn is_production(&self) -> bool {
        self.app_env.eq_ignore_ascii_case("production")
    }
}

fn non_empty(name: &str) -> Option<String> {
    env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn parse_env<T>(
    name: &str,
    default: T,
    range: std::ops::RangeInclusive<u64>,
) -> Result<T, ConfigError>
where
    T: std::str::FromStr + std::fmt::Display,
{
    let value = env::var(name)
        .ok()
        .map(|v| {
            v.parse::<u64>()
                .map_err(|_| ConfigError(format!("{name} must be an integer")))
        })
        .transpose()?
        .unwrap_or_else(|| default.to_string().parse::<u64>().expect("default parses"));
    if !range.contains(&value) {
        return Err(ConfigError(format!("{name} is outside its allowed range")));
    }
    value
        .to_string()
        .parse::<T>()
        .map_err(|_| ConfigError(format!("{name} has an invalid value")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_is_fixed() {
        assert_eq!(ALLOWED_ORIGIN, "https://vvc-office.pages.dev");
    }

    #[test]
    fn defaults_are_in_bounds() {
        assert!(parse_env("__VVC_TEST_MISSING__", 3000_u16, 1..=65535).is_ok());
    }
}

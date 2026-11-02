use std::{env, net::SocketAddr};

#[derive(Clone, Debug)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub app_env: String,
    pub session_idle_secs: u64,
    pub session_absolute_secs: u64,
    pub max_body_bytes: usize,
    pub gateway_secret: Option<String>,
    pub dev_password: String,
    pub cookie_secure: bool,
}

impl Config {
    pub fn from_env() -> Self {
        let port = env::var("PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3000);
        let app_env = env::var("APP_ENV").unwrap_or_else(|_| "development".into());
        let dev_password =
            env::var("AEGIS_DEV_PASSWORD").unwrap_or_else(|_| "ChangeMeNow!42".into());
        let gateway_secret = env::var("AEGIS_GATEWAY_SECRET")
            .ok()
            .filter(|v| !v.is_empty());
        let cookie_secure = env::var("COOKIE_SECURE")
            .map(|v| !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true);
        if app_env == "production" && dev_password == "ChangeMeNow!42" {
            tracing::warn!("AEGIS_DEV_PASSWORD is using the development placeholder; production bootstrap should provide a real secret");
        }
        Self {
            bind_addr: SocketAddr::from(([0, 0, 0, 0], port)),
            app_env,
            session_idle_secs: env::var("SESSION_IDLE_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1800),
            session_absolute_secs: env::var("SESSION_ABSOLUTE_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(28800),
            max_body_bytes: env::var("MAX_BODY_BYTES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1_048_576),
            gateway_secret,
            dev_password,
            cookie_secure,
        }
    }

    pub fn is_production(&self) -> bool {
        self.app_env.eq_ignore_ascii_case("production")
    }
}

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::http::HeaderMap;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

pub fn verify_password(password: &str, encoded: &str) -> bool {
    PasswordHash::new(encoded)
        .map(|hash| {
            Argon2::default()
                .verify_password(password.as_bytes(), &hash)
                .is_ok()
        })
        .unwrap_or(false)
}

pub fn random_token(bytes: usize) -> String {
    let mut buf = vec![0_u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

pub fn hash_session_token(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    raw.split(';').find_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        (key == name).then(|| value.to_string())
    })
}

/// Client IP, trusted only from `cf-connecting-ip`.
///
/// `x-real-ip` is deliberately ignored: any client can set it, so trusting it
/// lets an attacker rotate the apparent IP and bypass the per-IP login
/// throttle. `cf-connecting-ip` is set (and overwritten) by the Cloudflare
/// edge, and every proxy in this repo strips a client-supplied value before
/// forwarding. The value must also parse as a single IP address: lists such
/// as `1.2.3.4, 5.6.7.8`, garbage, and overly long values fall back to
/// `unknown` instead of poisoning rate-limit keys and `inet` columns.
pub fn client_ip(headers: &HeaderMap) -> String {
    headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty() && v.len() <= 45)
        .filter(|v| v.parse::<std::net::IpAddr>().is_ok())
        .unwrap_or("unknown")
        .to_string()
}

pub fn device(headers: &HeaderMap) -> String {
    headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.chars().take(160).collect())
        .unwrap_or_else(|| "unknown".into())
}
pub fn device_model(headers: &HeaderMap) -> String {
    headers
        .get("sec-ch-ua-model")
        .or_else(|| headers.get("x-device-model"))
        .and_then(|v| v.to_str().ok())
        .map(|v| v.chars().take(120).collect())
        .unwrap_or_else(|| "unknown".into())
}
pub fn device_fingerprint(headers: &HeaderMap) -> String {
    let material = format!(
        "{}|{}|{}|{}",
        device(headers),
        device_model(headers),
        headers
            .get("accept-language")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
        headers
            .get("sec-ch-ua-platform")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
    );
    Sha256::digest(material.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
pub fn constant_time_equal(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

pub fn session_cookie(token: &str, max_age: u64, secure: bool) -> String {
    if secure {
        format!("vvc_session={token}; Path=/; Max-Age={max_age}; HttpOnly; Secure; SameSite=None")
    } else {
        format!("vvc_session={token}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Lax")
    }
}
pub fn csrf_cookie(token: &str, max_age: u64, secure: bool) -> String {
    // HttpOnly: browser JavaScript never reads this cookie directly — the
    // token is delivered to scripts via `GET /api/me` — so there is no
    // reason to expose it to `document.cookie` for an XSS payload to steal.
    if secure {
        format!("vvc_csrf={token}; Path=/; Max-Age={max_age}; HttpOnly; Secure; SameSite=None")
    } else {
        format!("vvc_csrf={token}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Lax")
    }
}
pub fn expired_session_cookie(secure: bool) -> String {
    if secure {
        "vvc_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None".into()
    } else {
        "vvc_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax".into()
    }
}
pub fn expired_csrf_cookie(secure: bool) -> String {
    if secure {
        "vvc_csrf=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None".into()
    } else {
        "vvc_csrf=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax".into()
    }
}

/// Common-password and weak-password rejection for user creation and
/// password changes. This is a small denylist, not a substitute for a
/// breached-password check, but it stops the weakest choices outright.
pub fn is_weak_password(password: &str, username: &str, email: &str) -> bool {
    const COMMON: [&str; 12] = [
        "password",
        "password123",
        "password1234",
        "123456789012",
        "1234567890",
        "qwerty123456",
        "letmein12345",
        "admin123456",
        "changeme123",
        "welcome12345",
        "vvc123456789",
        "superadmin12",
    ];
    let lower = password.to_ascii_lowercase();
    if COMMON.contains(&lower.as_str()) {
        return true;
    }
    let user = username.to_ascii_lowercase();
    if !user.is_empty() && lower.contains(&user) {
        return true;
    }
    if let Some(local) = email.split('@').next() {
        let local = local.to_ascii_lowercase();
        if local.len() >= 4 && lower.contains(&local) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    fn headers_with(name: &str, value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            name.parse::<axum::http::HeaderName>().unwrap(),
            axum::http::HeaderValue::from_str(value).unwrap(),
        );
        headers
    }

    #[test]
    fn client_ip_accepts_only_a_single_valid_ip() {
        assert_eq!(
            client_ip(&headers_with("cf-connecting-ip", "203.0.113.10")),
            "203.0.113.10"
        );
        // Lists, garbage and spoofable x-real-ip must not be trusted.
        assert_eq!(
            client_ip(&headers_with(
                "cf-connecting-ip",
                "203.0.113.10, 198.51.100.1"
            )),
            "unknown"
        );
        assert_eq!(
            client_ip(&headers_with("cf-connecting-ip", "not-an-ip")),
            "unknown"
        );
        assert_eq!(
            client_ip(&headers_with("x-real-ip", "203.0.113.10")),
            "unknown"
        );
        assert_eq!(client_ip(&HeaderMap::new()), "unknown");
    }

    #[test]
    fn weak_passwords_are_rejected() {
        assert!(is_weak_password("password1234", "ops", "ops@example.com"));
        assert!(is_weak_password("ops-secret-99", "ops", "ops@example.com"));
        assert!(!is_weak_password(
            "correct horse battery staple",
            "ops",
            "ops@example.com"
        ));
    }
}

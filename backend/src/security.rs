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

pub fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    raw.split(';').find_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        (key == name).then(|| value.to_string())
    })
}

pub fn client_ip(headers: &HeaderMap) -> String {
    headers
        .get("cf-connecting-ip")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.len() <= 128)
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
        format!("aegis_session={token}; Path=/; Max-Age={max_age}; HttpOnly; Secure; SameSite=None")
    } else {
        format!("aegis_session={token}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Lax")
    }
}
pub fn expired_session_cookie(secure: bool) -> String {
    if secure {
        "aegis_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None".into()
    } else {
        "aegis_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax".into()
    }
}

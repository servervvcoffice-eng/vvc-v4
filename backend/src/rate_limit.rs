use redis::{aio::MultiplexedConnection, AsyncCommands, Script};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

const WINDOW_SECONDS: usize = 60;
const MAX_ATTEMPTS: u64 = 8;
const KEY_PREFIX: &str = "vvc:login:v1:";

#[derive(Clone)]
pub struct LoginRateLimiter {
    backend: Backend,
}

#[derive(Clone)]
enum Backend {
    Redis {
        connection: Arc<Mutex<MultiplexedConnection>>,
    },
    Memory {
        buckets: Arc<Mutex<HashMap<String, MemoryBucket>>>,
    },
}

#[derive(Clone, Copy)]
struct MemoryBucket {
    window_started: u64,
    attempts: u64,
}

impl LoginRateLimiter {
    pub async fn connect(redis_url: Option<&str>, production: bool) -> Result<Self, String> {
        let Some(redis_url) = redis_url else {
            if production {
                return Err("REDIS_URL is required in production".into());
            }
            return Ok(Self {
                backend: Backend::Memory {
                    buckets: Arc::new(Mutex::new(HashMap::new())),
                },
            });
        };

        let client = redis::Client::open(redis_url).map_err(|error| error.to_string())?;
        let mut connection = client
            .get_multiplexed_async_connection()
            .await
            .map_err(|error| error.to_string())?;
        redis::cmd("PING")
            .query_async::<String>(&mut connection)
            .await
            .map_err(|error| error.to_string())?;
        Ok(Self {
            backend: Backend::Redis {
                connection: Arc::new(Mutex::new(connection)),
            },
        })
    }

    pub async fn is_throttled(&self, ip: &str) -> Result<bool, String> {
        match &self.backend {
            Backend::Redis { connection } => {
                let mut connection = connection.lock().await;
                let count: Option<u64> = connection
                    .get(redis_key(ip))
                    .await
                    .map_err(|error| error.to_string())?;
                Ok(count.unwrap_or(0) >= MAX_ATTEMPTS)
            }
            Backend::Memory { buckets } => {
                let now = crate::store::now();
                let mut buckets = buckets.lock().await;
                let bucket = buckets.entry(ip.to_string()).or_insert(MemoryBucket {
                    window_started: now,
                    attempts: 0,
                });
                if now.saturating_sub(bucket.window_started) > WINDOW_SECONDS as u64 {
                    bucket.window_started = now;
                    bucket.attempts = 0;
                }
                Ok(bucket.attempts >= MAX_ATTEMPTS)
            }
        }
    }

    pub async fn record_failure(&self, ip: &str) -> Result<(), String> {
        match &self.backend {
            Backend::Redis { connection } => {
                let mut connection = connection.lock().await;
                let script = Script::new(concat!(
                    "local count = redis.call('INCR', KEYS[1])\n",
                    "if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end\n",
                    "return count"
                ));
                script
                    .key(redis_key(ip))
                    .arg(WINDOW_SECONDS)
                    .invoke_async::<u64>(&mut *connection)
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            }
            Backend::Memory { buckets } => {
                let now = crate::store::now();
                let mut buckets = buckets.lock().await;
                let bucket = buckets.entry(ip.to_string()).or_insert(MemoryBucket {
                    window_started: now,
                    attempts: 0,
                });
                if now.saturating_sub(bucket.window_started) > WINDOW_SECONDS as u64 {
                    bucket.window_started = now;
                    bucket.attempts = 0;
                }
                bucket.attempts = bucket.attempts.saturating_add(1);
                Ok(())
            }
        }
    }

    pub async fn clear(&self, ip: &str) -> Result<(), String> {
        match &self.backend {
            Backend::Redis { connection } => {
                let mut connection = connection.lock().await;
                connection
                    .del::<_, usize>(redis_key(ip))
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            }
            Backend::Memory { buckets } => {
                buckets.lock().await.remove(ip);
                Ok(())
            }
        }
    }

    pub async fn ready(&self) -> bool {
        match &self.backend {
            Backend::Memory { .. } => true,
            Backend::Redis { connection } => {
                let mut connection = connection.lock().await;
                redis::cmd("PING")
                    .query_async::<String>(&mut *connection)
                    .await
                    .is_ok()
            }
        }
    }
}

fn redis_key(ip: &str) -> String {
    let digest = Sha256::digest(ip.as_bytes());
    let hex = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{KEY_PREFIX}{hex}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_limiter_blocks_after_eight_failures_and_clears() {
        let limiter = LoginRateLimiter::connect(None, false).await.unwrap();
        assert!(!limiter.is_throttled("203.0.113.10").await.unwrap());
        for _ in 0..8 {
            limiter.record_failure("203.0.113.10").await.unwrap();
        }
        assert!(limiter.is_throttled("203.0.113.10").await.unwrap());
        limiter.clear("203.0.113.10").await.unwrap();
        assert!(!limiter.is_throttled("203.0.113.10").await.unwrap());
    }
}

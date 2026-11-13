use redis::{aio::MultiplexedConnection, AsyncCommands, Script};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

const WINDOW_SECONDS: usize = 60;
const LOGIN_MAX_ATTEMPTS: u64 = 8;
const LOGIN_KEY_PREFIX: &str = "vvc:login:v1:";
const GLOBAL_MAX_REQUESTS: u64 = 300;
const GLOBAL_KEY_PREFIX: &str = "vvc:global:v1:";
/// Bound on in-memory buckets so a flood of distinct IPs cannot grow the
/// map without limit in the process-local fallback.
const MAX_MEMORY_BUCKETS: usize = 10_000;

#[derive(Clone)]
pub struct LoginRateLimiter {
    backend: Backend,
    key_prefix: String,
    max_attempts: u64,
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
        Self::connect_with(redis_url, production, LOGIN_KEY_PREFIX, LOGIN_MAX_ATTEMPTS).await
    }

    /// Global throttle for every non-health request (300/min per IP).
    /// Without this, only login was throttled and any other endpoint —
    /// including the spam-logging path itself — could be hammered freely.
    pub async fn connect_global(redis_url: Option<&str>, production: bool) -> Result<Self, String> {
        Self::connect_with(
            redis_url,
            production,
            GLOBAL_KEY_PREFIX,
            GLOBAL_MAX_REQUESTS,
        )
        .await
    }

    async fn connect_with(
        redis_url: Option<&str>,
        production: bool,
        key_prefix: &str,
        max_attempts: u64,
    ) -> Result<Self, String> {
        let Some(redis_url) = redis_url else {
            if production {
                return Err("REDIS_URL is required in production".into());
            }
            return Ok(Self {
                backend: Backend::Memory {
                    buckets: Arc::new(Mutex::new(HashMap::new())),
                },
                key_prefix: key_prefix.to_string(),
                max_attempts,
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
            key_prefix: key_prefix.to_string(),
            max_attempts,
        })
    }

    pub async fn is_throttled(&self, key: &str) -> Result<bool, String> {
        match &self.backend {
            Backend::Redis { connection } => {
                let mut connection = connection.lock().await;
                let count: Option<u64> = connection
                    .get(self.redis_key(key))
                    .await
                    .map_err(|error| error.to_string())?;
                Ok(count.unwrap_or(0) >= self.max_attempts)
            }
            Backend::Memory { buckets } => {
                let now = crate::store::now();
                let mut buckets = buckets.lock().await;
                prune_buckets(&mut buckets, now);
                let bucket = buckets.entry(key.to_string()).or_insert(MemoryBucket {
                    window_started: now,
                    attempts: 0,
                });
                if now.saturating_sub(bucket.window_started) > WINDOW_SECONDS as u64 {
                    bucket.window_started = now;
                    bucket.attempts = 0;
                }
                Ok(bucket.attempts >= self.max_attempts)
            }
        }
    }

    pub async fn record_failure(&self, key: &str) -> Result<(), String> {
        match &self.backend {
            Backend::Redis { connection } => {
                let mut connection = connection.lock().await;
                let script = Script::new(concat!(
                    "local count = redis.call('INCR', KEYS[1])\n",
                    "if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end\n",
                    "return count"
                ));
                script
                    .key(self.redis_key(key))
                    .arg(WINDOW_SECONDS)
                    .invoke_async::<u64>(&mut *connection)
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            }
            Backend::Memory { buckets } => {
                let now = crate::store::now();
                let mut buckets = buckets.lock().await;
                prune_buckets(&mut buckets, now);
                let bucket = buckets.entry(key.to_string()).or_insert(MemoryBucket {
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

    pub async fn clear(&self, key: &str) -> Result<(), String> {
        match &self.backend {
            Backend::Redis { connection } => {
                let mut connection = connection.lock().await;
                connection
                    .del::<_, usize>(self.redis_key(key))
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            }
            Backend::Memory { buckets } => {
                buckets.lock().await.remove(key);
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

    fn redis_key(&self, key: &str) -> String {
        let digest = Sha256::digest(key.as_bytes());
        let hex = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!("{}{hex}", self.key_prefix)
    }
}

fn prune_buckets(buckets: &mut HashMap<String, MemoryBucket>, now: u64) {
    if buckets.len() <= MAX_MEMORY_BUCKETS {
        return;
    }
    buckets.retain(|_, bucket| now.saturating_sub(bucket.window_started) <= WINDOW_SECONDS as u64);
    if buckets.len() > MAX_MEMORY_BUCKETS {
        // Still over budget (all recent): drop the oldest windows first.
        let mut entries: Vec<_> = buckets
            .iter()
            .map(|(k, b)| (k.clone(), b.window_started))
            .collect();
        entries.sort_by_key(|(_, started)| *started);
        for (key, _) in entries.into_iter().take(buckets.len() - MAX_MEMORY_BUCKETS) {
            buckets.remove(&key);
        }
    }
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

    #[tokio::test]
    async fn global_limiter_allows_normal_traffic_and_blocks_floods() {
        let limiter = LoginRateLimiter::connect_global(None, false).await.unwrap();
        for _ in 0..299 {
            limiter.record_failure("203.0.113.10").await.unwrap();
        }
        assert!(!limiter.is_throttled("203.0.113.10").await.unwrap());
        limiter.record_failure("203.0.113.10").await.unwrap();
        assert!(limiter.is_throttled("203.0.113.10").await.unwrap());
    }
}

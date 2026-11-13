use crate::{config::Config, rate_limit::LoginRateLimiter, security};
use serde::{Deserialize, Serialize};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    PgPool, Row,
};
use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::RwLock;

pub const ALL_PERMISSIONS: [&str; 17] = [
    "home.read",
    "about.read",
    "admin.dashboard.read",
    "admin.users.read",
    "admin.users.create",
    "admin.users.update_role",
    "admin.users.block",
    "admin.users.delete",
    "admin.views.read",
    "admin.views.clear",
    "admin.activity.read",
    "admin.activity.clear",
    "admin.failed_logins.read",
    "admin.failed_logins.clear",
    "admin.audit_logs.read",
    "admin.spam.read",
    "admin.spam.clear",
];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    SuperAdmin,
    Admin,
    User,
}

impl Role {
    pub fn label(&self) -> &'static str {
        match self {
            Self::SuperAdmin => "Super Admin",
            Self::Admin => "Admin",
            Self::User => "User",
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SuperAdmin => "super_admin",
            Self::Admin => "admin",
            Self::User => "viewer",
        }
    }
}

#[derive(Clone, Debug)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub role: Role,
    pub delegated_permissions: HashSet<String>,
    pub blocked: bool,
    pub failed_login_count: u32,
    pub last_login: Option<u64>,
    pub created_at: u64,
}

#[derive(Clone, Debug)]
pub struct Session {
    pub user_id: String,
    pub created_at: u64,
    pub last_seen: u64,
    pub csrf_token: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ActivityLog {
    pub id: String,
    pub user: String,
    pub action: String,
    pub details: String,
    pub ip: String,
    pub timestamp: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct ViewLog {
    pub id: String,
    pub page: String,
    pub user: String,
    pub ip: String,
    pub device: String,
    pub timestamp: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct FailedLogin {
    pub id: String,
    pub attempted_username: String,
    pub ip: String,
    pub device: String,
    pub timestamp: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct AuditLog {
    pub id: String,
    pub actor: String,
    pub action: String,
    pub details: String,
    pub ip: String,
    pub timestamp: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct SpamLog {
    pub id: String,
    pub username: String,
    pub ip: String,
    pub device_fingerprint: String,
    pub device_model: String,
    pub device: String,
    pub route: String,
    pub method: String,
    pub status: u16,
    pub timestamp: u64,
}
pub struct Store {
    pub users: HashMap<String, User>,
    pub sessions: HashMap<String, Session>,
    pub activity: Vec<ActivityLog>,
    pub views: Vec<ViewLog>,
    pub failed_logins: Vec<FailedLogin>,
    pub audits: Vec<AuditLog>,
    pub spam: Vec<SpamLog>,
}

#[derive(Clone)]
pub struct AppState {
    pub pub_store: Arc<RwLock<Store>>,
    pub config: Config,
    pub persistence: Option<Arc<Persistence>>,
    pub login_limiter: LoginRateLimiter,
    /// Per-username login throttle (same 8/min budget, keyed by the
    /// lower-cased username). Without it, an attacker can stuff one
    /// account's password from many IPs and the per-IP limiter never fires.
    pub account_limiter: LoginRateLimiter,
    /// Global per-IP throttle for all non-health requests.
    pub global_limiter: LoginRateLimiter,
}

#[derive(Clone)]
pub struct Persistence {
    pool: PgPool,
}

impl Persistence {
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        let options = PgConnectOptions::from_str(database_url)?.statement_cache_capacity(0);
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await?;
        sqlx::query("select 1")
            .persistent(false)
            .execute(&pool)
            .await?;
        Ok(Self { pool })
    }

    pub async fn load_users(&self, store: &mut Store) -> Result<usize, sqlx::Error> {
        let rows = sqlx::query(
            "select id::text as id, username, email, password_hash, blocked, failed_login_count,
                    floor(extract(epoch from last_login_at))::bigint as last_login,
                    floor(extract(epoch from created_at))::bigint as created_at
             from users order by created_at asc",
        )
        .persistent(false)
        .fetch_all(&self.pool)
        .await?;
        if rows.is_empty() {
            return Ok(0);
        }
        let mut users = HashMap::new();
        for row in rows {
            let id: String = row.try_get("id")?;
            let role_id: Option<String> = sqlx::query_scalar(
                "select role_id from user_roles where user_id = $1::uuid order by role_id limit 1",
            )
            .persistent(false)
            .bind(&id)
            .fetch_optional(&self.pool)
            .await?;
            let role = match role_id.as_deref() {
                Some("super_admin") => Role::SuperAdmin,
                Some("admin") => Role::Admin,
                _ => Role::User,
            };
            let delegated_permissions = permissions_for_role(&role);
            users.insert(
                id.clone(),
                User {
                    id,
                    username: row.try_get("username")?,
                    email: row.try_get("email")?,
                    password_hash: row.try_get("password_hash")?,
                    role,
                    delegated_permissions,
                    blocked: row.try_get("blocked")?,
                    failed_login_count: row.try_get::<i32, _>("failed_login_count")?.max(0) as u32,
                    last_login: row
                        .try_get::<Option<i64>, _>("last_login")?
                        .map(|v| v as u64),
                    created_at: row.try_get::<i64, _>("created_at")? as u64,
                },
            );
        }
        store.users = users;
        Ok(store.users.len())
    }

    async fn user_query(&self, predicate: &str, value: &str) -> Result<Option<User>, sqlx::Error> {
        let query = format!(
            "select u.id::text as id, u.username, u.email, u.password_hash, u.blocked,
                    u.failed_login_count, floor(extract(epoch from u.last_login_at))::bigint as last_login,
                    floor(extract(epoch from u.created_at))::bigint as created_at,
                    coalesce(r.role_id, 'viewer') as role_id
             from users u
             left join lateral (select role_id from user_roles where user_id = u.id order by role_id limit 1) r on true
             where {predicate}
             limit 1"
        );
        let row = sqlx::query(&query)
            .persistent(false)
            .bind(value)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| {
            let role = match row.try_get::<String, _>("role_id")?.as_str() {
                "super_admin" => Role::SuperAdmin,
                "admin" => Role::Admin,
                _ => Role::User,
            };
            Ok(User {
                id: row.try_get("id")?,
                username: row.try_get("username")?,
                email: row.try_get("email")?,
                password_hash: row.try_get("password_hash")?,
                delegated_permissions: permissions_for_role(&role),
                role,
                blocked: row.try_get("blocked")?,
                failed_login_count: row.try_get::<i32, _>("failed_login_count")?.max(0) as u32,
                last_login: row
                    .try_get::<Option<i64>, _>("last_login")?
                    .map(|v| v.max(0) as u64),
                created_at: row.try_get::<i64, _>("created_at")?.max(0) as u64,
            })
        })
        .transpose()
    }

    pub async fn user_by_username(&self, username: &str) -> Result<Option<User>, sqlx::Error> {
        self.user_query("lower(u.username) = lower($1)", username)
            .await
    }

    pub async fn user_by_id(&self, id: &str) -> Result<Option<User>, sqlx::Error> {
        if uuid::Uuid::parse_str(id).is_err() {
            return Ok(None);
        }
        self.user_query("u.id = $1::uuid", id).await
    }

    pub async fn user_counts(&self) -> Result<(i64, i64), sqlx::Error> {
        sqlx::query_as(
            "select count(*)::bigint, count(*) filter (where blocked)::bigint from users",
        )
        .persistent(false)
        .fetch_one(&self.pool)
        .await
    }

    /// Creates the initial superadmin exactly once. The advisory transaction lock
    /// prevents two booting instances from racing; an existing user means the
    /// bootstrap is permanently skipped.
    pub async fn bootstrap_superadmin(
        &self,
        email: &str,
        password_hash: &str,
    ) -> Result<bool, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("select pg_advisory_xact_lock(hashtext('vvc-office-bootstrap'))")
            .persistent(false)
            .execute(&mut *tx)
            .await?;
        let existing: i64 = sqlx::query_scalar("select count(*) from users")
            .persistent(false)
            .fetch_one(&mut *tx)
            .await?;
        if existing > 0 {
            tx.rollback().await?;
            return Ok(false);
        }
        let user_id: uuid::Uuid = sqlx::query_scalar(
            "insert into users (username, email, password_hash) values ('superadmin', $1, $2) returning id",
        )
        .persistent(false)
        .bind(email)
        .bind(password_hash)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query("insert into user_roles (user_id, role_id) values ($1, 'super_admin')")
            .persistent(false)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(true)
    }

    pub async fn list_users(
        &self,
        search: &str,
        page: usize,
        limit: usize,
    ) -> Result<(Vec<User>, i64), sqlx::Error> {
        let pattern = format!("%{}%", search.to_lowercase());
        let total: i64 = sqlx::query_scalar("select count(*) from users u left join lateral (select role_id from user_roles where user_id = u.id order by role_id limit 1) r on true where $1 = '%%' or lower(u.username || ' ' || u.email || ' ' || coalesce(r.role_id, 'viewer')) like $1")
            .persistent(false).bind(&pattern).fetch_one(&self.pool).await?;
        let rows = sqlx::query("select u.id::text as id, u.username, u.email, u.password_hash, u.blocked, u.failed_login_count, floor(extract(epoch from u.last_login_at))::bigint as last_login, floor(extract(epoch from u.created_at))::bigint as created_at, coalesce(r.role_id, 'viewer') as role_id from users u left join lateral (select role_id from user_roles where user_id = u.id order by role_id limit 1) r on true where $1 = '%%' or lower(u.username || ' ' || u.email || ' ' || coalesce(r.role_id, 'viewer')) like $1 order by u.created_at asc limit $2 offset $3")
            .persistent(false).bind(&pattern).bind(limit as i64).bind(page.saturating_mul(limit) as i64).fetch_all(&self.pool).await?;
        let users = rows
            .into_iter()
            .map(|row| {
                let role = match row.try_get::<String, _>("role_id")?.as_str() {
                    "super_admin" => Role::SuperAdmin,
                    "admin" => Role::Admin,
                    _ => Role::User,
                };
                Ok(User {
                    id: row.try_get("id")?,
                    username: row.try_get("username")?,
                    email: row.try_get("email")?,
                    password_hash: row.try_get("password_hash")?,
                    role: role.clone(),
                    delegated_permissions: permissions_for_role(&role),
                    blocked: row.try_get("blocked")?,
                    failed_login_count: row.try_get::<i32, _>("failed_login_count")?.max(0) as u32,
                    last_login: row
                        .try_get::<Option<i64>, _>("last_login")?
                        .map(|v| v.max(0) as u64),
                    created_at: row.try_get::<i64, _>("created_at")?.max(0) as u64,
                })
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()?;
        Ok((users, total))
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn create_user(
        &self,
        username: &str,
        email: &str,
        password_hash: &str,
        role: &Role,
        actor_id: &str,
        actor: &str,
        details: &str,
        ip: &str,
    ) -> Result<String, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let id: uuid::Uuid = sqlx::query_scalar(
            "insert into users (username, email, password_hash) values ($1, $2, $3) returning id",
        )
        .persistent(false)
        .bind(username)
        .bind(email)
        .bind(password_hash)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query("insert into user_roles (user_id, role_id) values ($1, $2)")
            .persistent(false)
            .bind(id)
            .bind(role.as_str())
            .execute(&mut *tx)
            .await?;
        sqlx::query("insert into activity_logs (user_id, username_snapshot, action, details, ip_address) values ($1, $2, 'user.created', $3, nullif($4, '')::inet)").persistent(false).bind(uuid::Uuid::parse_str(actor_id).ok()).bind(actor).bind(details).bind(ip).execute(&mut *tx).await?;
        sqlx::query("insert into audit_logs (actor_user_id, action, details, ip_address) values ($1, 'user.created', jsonb_build_object('actor', $2, 'message', $3), nullif($4, '')::inet)").persistent(false).bind(uuid::Uuid::parse_str(actor_id).ok()).bind(actor).bind(details).bind(ip).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(id.to_string())
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn update_role(
        &self,
        id: &str,
        role: &Role,
        actor_id: &str,
        actor: &str,
        details: &str,
        ip: &str,
    ) -> Result<bool, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let target: Option<(uuid::Uuid, String, bool)> = sqlx::query_as("select u.id, coalesce(r.role_id, 'viewer'), u.blocked from users u left join lateral (select role_id from user_roles where user_id = u.id order by role_id limit 1) r on true where u.id = $1::uuid for update").persistent(false).bind(id).fetch_optional(&mut *tx).await?;
        let Some((user_id, old_role, blocked)) = target else {
            tx.rollback().await?;
            return Ok(false);
        };
        if old_role == "super_admin" && role != &Role::SuperAdmin && !blocked {
            let active: i64 = sqlx::query_scalar("select count(*) from users u join user_roles r on r.user_id = u.id where r.role_id = 'super_admin' and not u.blocked").persistent(false).fetch_one(&mut *tx).await?;
            if active <= 1 {
                return Err(sqlx::Error::Protocol("last active super admin".into()));
            }
        }
        sqlx::query("delete from user_roles where user_id = $1")
            .persistent(false)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("insert into user_roles (user_id, role_id) values ($1, $2)")
            .persistent(false)
            .bind(user_id)
            .bind(role.as_str())
            .execute(&mut *tx)
            .await?;
        sqlx::query("delete from sessions where user_id = $1")
            .persistent(false)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("insert into activity_logs (user_id, username_snapshot, action, details, ip_address) values ($1, $2, 'user.role_changed', $3, nullif($4, '')::inet)").persistent(false).bind(uuid::Uuid::parse_str(actor_id).ok()).bind(actor).bind(details).bind(ip).execute(&mut *tx).await?;
        sqlx::query("insert into audit_logs (actor_user_id, action, details, ip_address) values ($1, 'user.role_changed', jsonb_build_object('actor', $2, 'message', $3), nullif($4, '')::inet)").persistent(false).bind(uuid::Uuid::parse_str(actor_id).ok()).bind(actor).bind(details).bind(ip).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(true)
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn set_blocked(
        &self,
        id: &str,
        blocked: bool,
        actor_id: &str,
        actor: &str,
        action: &str,
        details: &str,
        ip: &str,
    ) -> Result<bool, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let target: Option<(uuid::Uuid, String, bool)> = sqlx::query_as("select u.id, coalesce(r.role_id, 'viewer'), u.blocked from users u left join lateral (select role_id from user_roles where user_id = u.id order by role_id limit 1) r on true where u.id = $1::uuid for update").persistent(false).bind(id).fetch_optional(&mut *tx).await?;
        let Some((user_id, role, old_blocked)) = target else {
            tx.rollback().await?;
            return Ok(false);
        };
        if blocked && role == "super_admin" && !old_blocked {
            let active: i64 = sqlx::query_scalar("select count(*) from users u join user_roles r on r.user_id = u.id where r.role_id = 'super_admin' and not u.blocked").persistent(false).fetch_one(&mut *tx).await?;
            if active <= 1 {
                return Err(sqlx::Error::Protocol("last active super admin".into()));
            }
        }
        sqlx::query("update users set blocked = $2, updated_at = now() where id = $1")
            .persistent(false)
            .bind(user_id)
            .bind(blocked)
            .execute(&mut *tx)
            .await?;
        if blocked {
            sqlx::query("delete from sessions where user_id = $1")
                .persistent(false)
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query("insert into activity_logs (user_id, username_snapshot, action, details, ip_address) values ($1, $2, $3, $4, nullif($5, '')::inet)").persistent(false).bind(uuid::Uuid::parse_str(actor_id).ok()).bind(actor).bind(action).bind(details).bind(ip).execute(&mut *tx).await?;
        sqlx::query("insert into audit_logs (actor_user_id, action, details, ip_address) values ($1, $2, jsonb_build_object('actor', $3, 'message', $4), nullif($5, '')::inet)").persistent(false).bind(uuid::Uuid::parse_str(actor_id).ok()).bind(action).bind(actor).bind(details).bind(ip).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(true)
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn delete_user(
        &self,
        id: &str,
        actor_id: &str,
        actor: &str,
        details: &str,
        ip: &str,
    ) -> Result<bool, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let target: Option<(uuid::Uuid, String, bool)> = sqlx::query_as("select u.id, coalesce(r.role_id, 'viewer'), u.blocked from users u left join lateral (select role_id from user_roles where user_id = u.id order by role_id limit 1) r on true where u.id = $1::uuid for update").persistent(false).bind(id).fetch_optional(&mut *tx).await?;
        let Some((user_id, role, blocked)) = target else {
            tx.rollback().await?;
            return Ok(false);
        };
        if role == "super_admin" && !blocked {
            let active: i64 = sqlx::query_scalar("select count(*) from users u join user_roles r on r.user_id = u.id where r.role_id = 'super_admin' and not u.blocked").persistent(false).fetch_one(&mut *tx).await?;
            if active <= 1 {
                return Err(sqlx::Error::Protocol("last active super admin".into()));
            }
        }
        sqlx::query("delete from sessions where user_id = $1")
            .persistent(false)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("insert into activity_logs (user_id, username_snapshot, action, details, ip_address) values ($1, $2, 'user.deleted', $3, nullif($4, '')::inet)").persistent(false).bind(uuid::Uuid::parse_str(actor_id).ok()).bind(actor).bind(details).bind(ip).execute(&mut *tx).await?;
        sqlx::query("insert into audit_logs (actor_user_id, action, details, ip_address) values ($1, 'user.deleted', jsonb_build_object('actor', $2, 'message', $3), nullif($4, '')::inet)").persistent(false).bind(uuid::Uuid::parse_str(actor_id).ok()).bind(actor).bind(details).bind(ip).execute(&mut *tx).await?;
        sqlx::query("delete from users where id = $1")
            .persistent(false)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(true)
    }

    #[allow(dead_code)]
    pub async fn sync_users(&self, store: &Store) -> Result<(), sqlx::Error> {
        for user in store.users.values() {
            if uuid::Uuid::parse_str(&user.id).is_err() {
                continue;
            }
            sqlx::query(
                "insert into users (id, username, email, password_hash, blocked, failed_login_count, last_login_at)
                 values ($1::uuid, $2, $3, $4, $5, $6, to_timestamp($7))
                 on conflict (id) do update set username=excluded.username, email=excluded.email,
                 password_hash=excluded.password_hash, blocked=excluded.blocked,
                 failed_login_count=excluded.failed_login_count, last_login_at=excluded.last_login_at,
                 updated_at=now()",
            )
            .persistent(false)
            .bind(&user.id)
            .bind(&user.username)
            .bind(&user.email)
            .bind(&user.password_hash)
            .bind(user.blocked)
            .bind(user.failed_login_count as i32)
            .bind(user.last_login.map(|v| v as i64))
            .execute(&self.pool)
            .await?;
            sqlx::query("delete from user_roles where user_id = $1::uuid")
                .persistent(false)
                .bind(&user.id)
                .execute(&self.pool)
                .await?;
            sqlx::query("insert into user_roles(user_id, role_id) values ($1::uuid, $2) on conflict do nothing")
                .persistent(false)
                .bind(&user.id)
                .bind(user.role.as_str())
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }

    pub async fn create_session(
        &self,
        session_id: &str,
        user_id: &str,
        csrf_token: &str,
        now: u64,
        expires_at: u64,
    ) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("delete from sessions where user_id = $1::uuid")
            .persistent(false)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "insert into sessions (id_hash, user_id, csrf_token_hash, created_at, last_seen_at, expires_at)
             values ($1, $2::uuid, $3, to_timestamp($4), to_timestamp($4), to_timestamp($5))",
        )
        .persistent(false)
        .bind(security::hash_session_token(session_id))
        .bind(user_id)
        .bind(security::hash_session_token(csrf_token))
        .bind(now as i64)
        .bind(expires_at as i64)
        .execute(&mut *tx)
        .await?;
        tx.commit().await
    }

    pub async fn session(
        &self,
        session_id: &str,
    ) -> Result<Option<(String, String, u64, u64, u64)>, sqlx::Error> {
        let row = sqlx::query(
            "select user_id::text as user_id, csrf_token_hash,
                    floor(extract(epoch from created_at))::bigint as created_at,
                    floor(extract(epoch from last_seen_at))::bigint as last_seen_at,
                    floor(extract(epoch from expires_at))::bigint as expires_at
             from sessions where id_hash = $1",
        )
        .persistent(false)
        .bind(security::hash_session_token(session_id))
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else { return Ok(None) };
        Ok(Some((
            row.try_get("user_id")?,
            row.try_get("csrf_token_hash")?,
            row.try_get::<i64, _>("created_at")?.max(0) as u64,
            row.try_get::<i64, _>("last_seen_at")?.max(0) as u64,
            row.try_get::<i64, _>("expires_at")?.max(0) as u64,
        )))
    }

    pub async fn touch_session(&self, session_id: &str, now: u64) -> Result<(), sqlx::Error> {
        sqlx::query("update sessions set last_seen_at = to_timestamp($2) where id_hash = $1")
            .persistent(false)
            .bind(security::hash_session_token(session_id))
            .bind(now as i64)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn revoke_session(&self, session_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("delete from sessions where id_hash = $1")
            .persistent(false)
            .bind(security::hash_session_token(session_id))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn revoke_user_sessions(&self, user_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("delete from sessions where user_id = $1::uuid")
            .persistent(false)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    fn uuid_value(value: Option<&str>) -> Option<String> {
        value
            .filter(|value| uuid::Uuid::parse_str(value).is_ok())
            .map(str::to_owned)
    }

    pub async fn record_activity(
        &self,
        user_id: Option<&str>,
        username: &str,
        action: &str,
        details: &str,
        ip: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("insert into activity_logs (user_id, username_snapshot, action, details, ip_address) values ($1::uuid, $2, $3, $4, nullif($5, '')::inet)")
            .persistent(false)
            .bind(Self::uuid_value(user_id))
            .bind(username).bind(action).bind(details).bind(ip)
            .execute(&self.pool).await?;
        Ok(())
    }

    pub async fn record_view(
        &self,
        page: &str,
        user_id: Option<&str>,
        username: &str,
        ip: &str,
        device: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("insert into view_logs (page, user_id, username_snapshot, ip_address, device_info) values ($1, $2::uuid, $3, nullif($4, '')::inet, $5)")
            .persistent(false).bind(page).bind(Self::uuid_value(user_id)).bind(username)
            .bind(ip).bind(device).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn record_failed_login(
        &self,
        username: &str,
        ip: &str,
        device: &str,
    ) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("insert into login_attempts (attempted_username, ip_address, device_info, succeeded) values ($1, nullif($2, '')::inet, $3, false)")
            .persistent(false).bind(username).bind(ip).bind(device).execute(&mut *tx).await?;
        sqlx::query("update users set failed_login_count = failed_login_count + 1, updated_at = now() where lower(username) = lower($1)")
            .persistent(false).bind(username).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn record_login_success(
        &self,
        user_id: &str,
        username: &str,
        ip: &str,
        device: &str,
        now: u64,
    ) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("insert into login_attempts (attempted_username, ip_address, device_info, succeeded) values ($1, nullif($2, '')::inet, $3, true)")
            .persistent(false).bind(username).bind(ip).bind(device).execute(&mut *tx).await?;
        sqlx::query("update users set failed_login_count = 0, last_login_at = to_timestamp($2), updated_at = now() where id = $1::uuid")
            .persistent(false).bind(user_id).bind(now as i64).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn record_audit(
        &self,
        actor_id: Option<&str>,
        actor: &str,
        action: &str,
        details: &str,
        ip: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("insert into audit_logs (actor_user_id, action, details, ip_address) values ($1::uuid, $2, jsonb_build_object('actor', $3, 'message', $4), nullif($5, '')::inet)")
            .persistent(false).bind(Self::uuid_value(actor_id)).bind(action).bind(actor)
            .bind(details).bind(ip).execute(&self.pool).await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn record_spam(
        &self,
        username: &str,
        ip: &str,
        fingerprint: &str,
        model: &str,
        device: &str,
        route: &str,
        method: &str,
        status: u16,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("insert into spam_logs (username_snapshot, ip_address, device_fingerprint, device_model, device_info, route, method, status_code) values ($1, nullif($2, '')::inet, $3, $4, $5, $6, $7, $8)")
            .persistent(false).bind(username).bind(ip).bind(fingerprint).bind(model).bind(device)
            .bind(route).bind(method).bind(status as i32).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn activity(
        &self,
        start: Option<u64>,
        search: &str,
        page: usize,
        limit: usize,
    ) -> Result<Vec<ActivityLog>, sqlx::Error> {
        let rows = sqlx::query("select id::text as id, username_snapshot as username, action, details, coalesce(host(ip_address), '') as ip, floor(extract(epoch from created_at))::bigint as timestamp from activity_logs where ($1::bigint is null or extract(epoch from created_at) >= $1) and ($2 = '' or lower(username_snapshot || ' ' || action || ' ' || details) like '%' || lower($2) || '%') order by created_at desc limit $3 offset $4")
            .persistent(false).bind(start.map(|v| v as i64)).bind(search).bind(limit as i64).bind((page * limit) as i64).fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|row| {
                Ok(ActivityLog {
                    id: row.try_get("id")?,
                    user: row.try_get("username")?,
                    action: row.try_get("action")?,
                    details: row.try_get("details")?,
                    ip: row.try_get("ip")?,
                    timestamp: row.try_get::<i64, _>("timestamp")?.max(0) as u64,
                })
            })
            .collect()
    }

    pub async fn views(
        &self,
        start: Option<u64>,
        page_name: &str,
        page: usize,
        limit: usize,
    ) -> Result<Vec<ViewLog>, sqlx::Error> {
        let rows = sqlx::query("select id::text as id, page, username_snapshot as username, coalesce(host(ip_address), '') as ip, coalesce(device_info, '') as device, floor(extract(epoch from created_at))::bigint as timestamp from view_logs where ($1::bigint is null or extract(epoch from created_at) >= $1) and ($2 = '' or lower(page) = lower($2)) order by created_at desc limit $3 offset $4")
            .persistent(false).bind(start.map(|v| v as i64)).bind(page_name).bind(limit as i64).bind((page * limit) as i64).fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|row| {
                Ok(ViewLog {
                    id: row.try_get("id")?,
                    page: row.try_get("page")?,
                    user: row.try_get("username")?,
                    ip: row.try_get("ip")?,
                    device: row.try_get("device")?,
                    timestamp: row.try_get::<i64, _>("timestamp")?.max(0) as u64,
                })
            })
            .collect()
    }

    pub async fn failed_logins(
        &self,
        start: Option<u64>,
        page: usize,
        limit: usize,
    ) -> Result<Vec<FailedLogin>, sqlx::Error> {
        let rows = sqlx::query("select id::text as id, attempted_username, coalesce(host(ip_address), '') as ip, coalesce(device_info, '') as device, floor(extract(epoch from created_at))::bigint as timestamp from login_attempts where not succeeded and ($1::bigint is null or extract(epoch from created_at) >= $1) order by created_at desc limit $2 offset $3")
            .persistent(false).bind(start.map(|v| v as i64)).bind(limit as i64).bind((page * limit) as i64).fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|row| {
                Ok(FailedLogin {
                    id: row.try_get("id")?,
                    attempted_username: row.try_get("attempted_username")?,
                    ip: row.try_get("ip")?,
                    device: row.try_get("device")?,
                    timestamp: row.try_get::<i64, _>("timestamp")?.max(0) as u64,
                })
            })
            .collect()
    }

    pub async fn audits(
        &self,
        start: Option<u64>,
        page: usize,
        limit: usize,
    ) -> Result<Vec<AuditLog>, sqlx::Error> {
        let rows = sqlx::query("select id::text as id, coalesce(details->>'actor', 'system') as actor, action, coalesce(details->>'message', details::text) as details, coalesce(host(ip_address), '') as ip, floor(extract(epoch from created_at))::bigint as timestamp from audit_logs where ($1::bigint is null or extract(epoch from created_at) >= $1) order by created_at desc limit $2 offset $3")
            .persistent(false).bind(start.map(|v| v as i64)).bind(limit as i64).bind((page * limit) as i64).fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|row| {
                Ok(AuditLog {
                    id: row.try_get("id")?,
                    actor: row.try_get("actor")?,
                    action: row.try_get("action")?,
                    details: row.try_get("details")?,
                    ip: row.try_get("ip")?,
                    timestamp: row.try_get::<i64, _>("timestamp")?.max(0) as u64,
                })
            })
            .collect()
    }

    pub async fn spam(
        &self,
        start: Option<u64>,
        search: &str,
        page: usize,
        limit: usize,
    ) -> Result<Vec<SpamLog>, sqlx::Error> {
        let rows = sqlx::query("select id::text as id, username_snapshot as username, coalesce(host(ip_address), '') as ip, device_fingerprint, coalesce(device_model, '') as device_model, coalesce(device_info, '') as device, route, method, status_code, floor(extract(epoch from created_at))::bigint as timestamp from spam_logs where ($1::bigint is null or extract(epoch from created_at) >= $1) and ($2 = '' or lower(username_snapshot || ' ' || host(ip_address) || ' ' || device_fingerprint || ' ' || coalesce(device_model, '') || ' ' || route || ' ' || method) like '%' || lower($2) || '%') order by created_at desc limit $3 offset $4")
            .persistent(false).bind(start.map(|v| v as i64)).bind(search).bind(limit as i64).bind((page * limit) as i64).fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|row| {
                Ok(SpamLog {
                    id: row.try_get("id")?,
                    username: row.try_get("username")?,
                    ip: row.try_get("ip")?,
                    device_fingerprint: row.try_get("device_fingerprint")?,
                    device_model: row.try_get("device_model")?,
                    device: row.try_get("device")?,
                    route: row.try_get("route")?,
                    method: row.try_get("method")?,
                    status: row
                        .try_get::<i32, _>("status_code")?
                        .clamp(0, u16::MAX as i32) as u16,
                    timestamp: row.try_get::<i64, _>("timestamp")?.max(0) as u64,
                })
            })
            .collect()
    }

    pub async fn count_since(&self, table: &str, start: Option<u64>) -> Result<i64, sqlx::Error> {
        let query = match table { "views" => "select count(*) from view_logs where ($1::bigint is null or extract(epoch from created_at) >= $1)", "spam" => "select count(*) from spam_logs where ($1::bigint is null or extract(epoch from created_at) >= $1)", "activity" => "select count(*) from activity_logs where ($1::bigint is null or extract(epoch from created_at) >= $1)", "audit" => "select count(*) from audit_logs where ($1::bigint is null or extract(epoch from created_at) >= $1)", _ => "select count(*) from login_attempts where not succeeded and ($1::bigint is null or extract(epoch from created_at) >= $1)" };
        sqlx::query_scalar(query)
            .persistent(false)
            .bind(start.map(|v| v as i64))
            .fetch_one(&self.pool)
            .await
    }

    pub async fn clear_logs(&self, kind: &str, start: Option<u64>) -> Result<(), sqlx::Error> {
        // Table names come only from this fixed match, never from user
        // input, so interpolating them is safe; every value is bound.
        // Clearing "failed" logins must not erase successful logins too:
        // previously it deleted every row in login_attempts, including the
        // successful-login audit trail.
        let (table, extra) = match kind {
            "views" => ("view_logs", ""),
            "activity" => ("activity_logs", ""),
            "spam" => ("spam_logs", ""),
            _ => ("login_attempts", "not succeeded and "),
        };
        let query = format!("delete from {table} where {extra}($1::bigint is null or extract(epoch from created_at) >= $1)");
        sqlx::query(&query)
            .persistent(false)
            .bind(start.map(|v| v as i64))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Retention job: delete operational logs older than `cutoff` (epoch
    /// seconds). Security audit logs are never deleted by this job.
    pub async fn delete_old_logs(&self, cutoff: u64) -> Result<(), sqlx::Error> {
        for table in ["view_logs", "activity_logs", "spam_logs", "login_attempts"] {
            let query = format!("delete from {table} where extract(epoch from created_at) < $1");
            sqlx::query(&query)
                .persistent(false)
                .bind(cutoff as i64)
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }

    /// Change a user's password hash and revoke every session for that
    /// user, so a changed password immediately invalidates sessions that
    /// may have been created with the old one.
    pub async fn update_password(
        &self,
        user_id: &str,
        password_hash: &str,
    ) -> Result<bool, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let updated = sqlx::query(
            "update users set password_hash = $2, failed_login_count = 0, updated_at = now() where id = $1::uuid",
        )
        .persistent(false)
        .bind(user_id)
        .bind(password_hash)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if updated == 0 {
            tx.rollback().await?;
            return Ok(false);
        }
        sqlx::query("delete from sessions where user_id = $1::uuid")
            .persistent(false)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(true)
    }
}

pub(crate) fn permissions_for_role(role: &Role) -> HashSet<String> {
    match role {
        Role::SuperAdmin => ALL_PERMISSIONS.iter().map(|s| (*s).to_string()).collect(),
        // Least privilege for delegated Admins: they can read the console
        // and block/unblock accounts, but destructive and privilege-granting
        // actions — creating users, deleting users, changing roles, and
        // clearing any log — are Super Admin only. Previously an Admin held
        // 16 of 17 permissions, so a compromised Admin account was nearly
        // as powerful as a Super Admin.
        Role::Admin => [
            "home.read",
            "about.read",
            "admin.dashboard.read",
            "admin.users.read",
            "admin.users.block",
            "admin.views.read",
            "admin.activity.read",
            "admin.failed_logins.read",
            "admin.spam.read",
        ]
        .into_iter()
        .map(str::to_string)
        .collect(),
        Role::User => ["home.read", "about.read"]
            .into_iter()
            .map(str::to_string)
            .collect(),
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub fn new_id() -> String {
    security::random_token(16)
}

/// Bound on each in-memory operational log. Previously these `Vec`s grew
/// forever — every request added a spam/view/activity entry — so a busy or
/// attacked server would eventually exhaust memory.
pub const MAX_MEMORY_LOG_ENTRIES: usize = 5_000;

fn push_capped<T>(log: &mut Vec<T>, entry: T) {
    if log.len() >= MAX_MEMORY_LOG_ENTRIES {
        let excess = log.len() - MAX_MEMORY_LOG_ENTRIES + 1;
        log.drain(..excess);
    }
    log.push(entry);
}

pub fn permissions_for(user: &User) -> HashSet<String> {
    if user.role == Role::SuperAdmin {
        return ALL_PERMISSIONS.iter().map(|s| (*s).to_string()).collect();
    }
    user.delegated_permissions.clone()
}

impl Store {
    pub fn empty() -> Self {
        Self {
            users: HashMap::new(),
            sessions: HashMap::new(),
            activity: Vec::new(),
            views: Vec::new(),
            failed_logins: Vec::new(),
            audits: Vec::new(),
            spam: Vec::new(),
        }
    }

    pub fn seeded(config: &Config) -> Self {
        let created_at = now();
        let password_hash =
            security::hash_password(&config.dev_password).expect("seed password must hash");
        let permissions = ALL_PERMISSIONS.iter().map(|s| (*s).to_string()).collect();
        let user = User {
            id: "usr_superadmin".into(),
            username: "superadmin".into(),
            email: "security@example.invalid".into(),
            password_hash,
            role: Role::SuperAdmin,
            delegated_permissions: permissions,
            blocked: false,
            failed_login_count: 0,
            last_login: None,
            created_at,
        };
        let mut users = HashMap::new();
        users.insert(user.id.clone(), user);
        Self {
            users,
            sessions: HashMap::new(),
            activity: Vec::new(),
            views: Vec::new(),
            failed_logins: Vec::new(),
            audits: Vec::new(),
            spam: Vec::new(),
        }
    }

    pub fn user_by_username(&self, username: &str) -> Option<User> {
        self.users
            .values()
            .find(|u| u.username.eq_ignore_ascii_case(username))
            .cloned()
    }
    pub fn user(&self, id: &str) -> Option<User> {
        self.users.get(id).cloned()
    }
    /// Drop in-memory operational logs older than `cutoff` (epoch secs).
    pub fn prune_old_logs(&mut self, cutoff: u64) {
        self.views.retain(|v| v.timestamp >= cutoff);
        self.activity.retain(|a| a.timestamp >= cutoff);
        self.failed_logins.retain(|f| f.timestamp >= cutoff);
        self.spam.retain(|s| s.timestamp >= cutoff);
    }

    pub fn active_super_admins(&self) -> usize {
        self.users
            .values()
            .filter(|u| u.role == Role::SuperAdmin && !u.blocked)
            .count()
    }

    pub fn add_activity(&mut self, user: &str, action: &str, details: &str, ip: &str) {
        push_capped(
            &mut self.activity,
            ActivityLog {
                id: new_id(),
                user: user.into(),
                action: action.into(),
                details: details.into(),
                ip: ip.into(),
                timestamp: now(),
            },
        );
    }
    pub fn add_view(&mut self, page: &str, user: &str, ip: &str, device: &str) {
        push_capped(
            &mut self.views,
            ViewLog {
                id: new_id(),
                page: page.into(),
                user: user.into(),
                ip: ip.into(),
                device: device.into(),
                timestamp: now(),
            },
        );
    }
    pub fn add_failed(&mut self, username: &str, ip: &str, device: &str) {
        push_capped(
            &mut self.failed_logins,
            FailedLogin {
                id: new_id(),
                attempted_username: username.into(),
                ip: ip.into(),
                device: device.into(),
                timestamp: now(),
            },
        );
    }
    pub fn add_audit(&mut self, actor: &str, action: &str, details: &str, ip: &str) {
        push_capped(
            &mut self.audits,
            AuditLog {
                id: new_id(),
                actor: actor.into(),
                action: action.into(),
                details: details.into(),
                ip: ip.into(),
                timestamp: now(),
            },
        );
    }
    #[allow(clippy::too_many_arguments)]
    pub fn add_spam(
        &mut self,
        username: &str,
        ip: &str,
        fingerprint: &str,
        model: &str,
        device: &str,
        route: &str,
        method: &str,
        status: u16,
    ) {
        push_capped(
            &mut self.spam,
            SpamLog {
                id: new_id(),
                username: username.into(),
                ip: ip.into(),
                device_fingerprint: fingerprint.into(),
                device_model: model.into(),
                device: device.into(),
                route: route.into(),
                method: method.into(),
                status,
                timestamp: now(),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_role_is_least_privilege() {
        let perms = permissions_for_role(&Role::Admin);
        // Destructive / privilege-granting actions are Super Admin only.
        for forbidden in [
            "admin.users.create",
            "admin.users.delete",
            "admin.users.update_role",
            "admin.views.clear",
            "admin.activity.clear",
            "admin.failed_logins.clear",
            "admin.spam.clear",
            "admin.audit_logs.read",
        ] {
            assert!(
                !perms.contains(forbidden),
                "{forbidden} must not be an Admin permission"
            );
        }
        for allowed in [
            "home.read",
            "admin.dashboard.read",
            "admin.users.read",
            "admin.users.block",
        ] {
            assert!(
                perms.contains(allowed),
                "{allowed} must be an Admin permission"
            );
        }
        assert_eq!(
            permissions_for_role(&Role::SuperAdmin).len(),
            ALL_PERMISSIONS.len()
        );
    }

    #[test]
    fn memory_logs_are_capped() {
        let mut store = Store::empty();
        for _ in 0..MAX_MEMORY_LOG_ENTRIES + 100 {
            store.add_activity("u", "login", "ok", "203.0.113.10");
        }
        assert_eq!(store.activity.len(), MAX_MEMORY_LOG_ENTRIES);
    }
}

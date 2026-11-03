use crate::{config::Config, security};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::{PgConnectOptions, PgPoolOptions}, PgPool, Row};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    str::FromStr,
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
#[derive(Clone, Debug)]
pub struct LoginBucket {
    pub window_started: u64,
    pub attempts: u32,
}

pub struct Store {
    pub users: HashMap<String, User>,
    pub sessions: HashMap<String, Session>,
    pub activity: Vec<ActivityLog>,
    pub views: Vec<ViewLog>,
    pub failed_logins: Vec<FailedLogin>,
    pub audits: Vec<AuditLog>,
    pub spam: Vec<SpamLog>,
    pub login_buckets: HashMap<String, LoginBucket>,
}

#[derive(Clone)]
pub struct AppState {
    pub pub_store: Arc<RwLock<Store>>,
    pub config: Config,
    pub persistence: Option<Arc<Persistence>>,
}

#[derive(Clone)]
pub struct Persistence {
    pool: PgPool,
}

impl Persistence {
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        let options = PgConnectOptions::from_str(database_url)?.statement_cache_capacity(0);
        let pool = PgPoolOptions::new().max_connections(4).connect_with(options).await?;
        sqlx::query("select 1").persistent(false).execute(&pool).await?;
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
                    last_login: row.try_get::<Option<i64>, _>("last_login")?.map(|v| v as u64),
                    created_at: row.try_get::<i64, _>("created_at")? as u64,
                },
            );
        }
        store.users = users;
        Ok(store.users.len())
    }

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
}

fn permissions_for_role(role: &Role) -> HashSet<String> {
    match role {
        Role::SuperAdmin => ALL_PERMISSIONS.iter().map(|s| (*s).to_string()).collect(),
        Role::Admin => ALL_PERMISSIONS
            .iter()
            .filter(|permission| **permission != "admin.audit_logs.read")
            .map(|s| (*s).to_string())
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

pub fn permissions_for(user: &User) -> HashSet<String> {
    if user.role == Role::SuperAdmin {
        return ALL_PERMISSIONS.iter().map(|s| (*s).to_string()).collect();
    }
    user.delegated_permissions.clone()
}

impl Store {
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
            login_buckets: HashMap::new(),
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
    pub fn active_super_admins(&self) -> usize {
        self.users
            .values()
            .filter(|u| u.role == Role::SuperAdmin && !u.blocked)
            .count()
    }

    pub fn add_activity(&mut self, user: &str, action: &str, details: &str, ip: &str) {
        self.activity.push(ActivityLog {
            id: new_id(),
            user: user.into(),
            action: action.into(),
            details: details.into(),
            ip: ip.into(),
            timestamp: now(),
        });
    }
    pub fn add_view(&mut self, page: &str, user: &str, ip: &str, device: &str) {
        self.views.push(ViewLog {
            id: new_id(),
            page: page.into(),
            user: user.into(),
            ip: ip.into(),
            device: device.into(),
            timestamp: now(),
        });
    }
    pub fn add_failed(&mut self, username: &str, ip: &str, device: &str) {
        self.failed_logins.push(FailedLogin {
            id: new_id(),
            attempted_username: username.into(),
            ip: ip.into(),
            device: device.into(),
            timestamp: now(),
        });
    }
    pub fn add_audit(&mut self, actor: &str, action: &str, details: &str, ip: &str) {
        self.audits.push(AuditLog {
            id: new_id(),
            actor: actor.into(),
            action: action.into(),
            details: details.into(),
            ip: ip.into(),
            timestamp: now(),
        });
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
        self.spam.push(SpamLog {
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
        });
    }
}

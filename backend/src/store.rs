use crate::{config::Config, security};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
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

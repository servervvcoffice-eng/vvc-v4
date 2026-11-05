use crate::{
    security,
    store::{self, AppState, AuditLog, FailedLogin, Role, User, ViewLog},
};
use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, Request, StatusCode},
    middleware::Next,
    response::{Html, IntoResponse, Redirect, Response},
    Json,
};
use include_dir::{include_dir, Dir};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::HashSet,
    path::{Path as FsPath, PathBuf},
};

const LOGIN_HTML: &str = include_str!("../public/login/index.html");
const LOGIN_CSS: &str = include_str!("../public/login/style.css");
const LOGIN_JS: &str = include_str!("../public/login/app.js");
const HOME_HTML: &str = include_str!("../project/home/index.html");
const HOME_CSS: &str = include_str!("../project/home/style.css");
const HOME_JS: &str = include_str!("../project/home/app.js");
const ABOUT_HTML: &str = include_str!("../project/about/index.html");
const ABOUT_CSS: &str = include_str!("../project/about/style.css");
const ABOUT_JS: &str = include_str!("../project/about/app.js");
const ADMIN_HTML: &str = include_str!("../project/admin/index.html");
const ADMIN_CSS: &str = "";
const ADMIN_JS: &str = "";
const NOT_FOUND_HTML: &str = include_str!("../public/404.html");
static ADMIN_DIR: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/project/admin");

#[derive(Clone)]
struct AuthContext {
    user: User,
    csrf_token: String,
}

#[derive(Deserialize)]
pub struct LoginPayload {
    username: String,
    password: String,
}
#[derive(Deserialize)]
pub struct CreateUserPayload {
    username: String,
    email: String,
    password: String,
    role: String,
}
#[derive(Deserialize)]
pub struct RolePayload {
    role: String,
}
#[derive(Deserialize, Default)]
pub struct ListQuery {
    pub range: Option<String>,
    pub page: Option<usize>,
    pub limit: Option<usize>,
    pub search: Option<String>,
    pub page_name: Option<String>,
}
#[derive(Serialize)]
struct MeResponse {
    id: String,
    username: String,
    email: String,
    role: String,
    role_label: String,
    permissions: Vec<String>,
    csrf_token: String,
}
#[derive(Clone, Serialize)]
struct UserSummary {
    id: String,
    username: String,
    email: String,
    role: String,
    role_label: String,
    blocked: bool,
    failed_login_count: u32,
    last_login: Option<u64>,
    created_at: u64,
}
#[derive(Serialize)]
struct Paged<T: Serialize> {
    items: Vec<T>,
    total: usize,
    page: usize,
    limit: usize,
}

pub async fn root(State(state): State<AppState>, headers: HeaderMap) -> Response {
    protected_page(&state, &headers, "home.read", HOME_HTML, "Home").await
}
pub async fn healthz() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        "ok",
    )
}
pub async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    if state.persistence.is_some() {
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            "ready",
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            "persistence unavailable",
        )
    }
}
pub async fn not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        NOT_FOUND_HTML,
    )
        .into_response()
}
pub async fn routes_manifest() -> impl IntoResponse {
    let mut routes = vec![
        json!({"path":"/", "title":"Home"}),
        json!({"path":"/login", "title":"Sign in"}),
        json!({"path":"/home", "title":"Home"}),
        json!({"path":"/about", "title":"About"}),
        json!({"path":"/admin", "title":"Admin"}),
    ];
    if let Ok(mut entries) = tokio::fs::read_dir(project_root()).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if !safe_segment(&name)
                || matches!(name.as_str(), "home" | "about" | "admin" | "login")
                || tokio::fs::metadata(path.join("index.html")).await.is_err()
            {
                continue;
            }
            routes.push(json!({"path": format!("/{name}"), "title": name}));
        }
    }
    routes.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    (
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        Json(json!({"routes": routes})),
    )
}
pub async fn login_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if auth_context(&state, &headers).await.is_some() {
        return Redirect::temporary("/home").into_response();
    }
    Html(LOGIN_HTML).into_response()
}
pub async fn login_css() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        LOGIN_CSS,
    )
}
pub async fn login_js() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        LOGIN_JS,
    )
}

pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<LoginPayload>,
) -> Response {
    let username = payload.username.trim().to_string();
    let ip = security::client_ip(&headers);
    let device = security::device(&headers);
    if username.is_empty()
        || username.len() > 64
        || payload.password.is_empty()
        || payload.password.len() > 256
    {
        return json_error(StatusCode::UNAUTHORIZED, "Invalid username or password");
    }
    let mut db = state.pub_store.write().await;
    let now = store::now();
    let throttled = {
        let bucket = db
            .login_buckets
            .entry(ip.clone())
            .or_insert(store::LoginBucket {
                window_started: now,
                attempts: 0,
            });
        if now.saturating_sub(bucket.window_started) > 60 {
            bucket.window_started = now;
            bucket.attempts = 0;
        }
        bucket.attempts >= 8
    };
    if throttled {
        db.add_failed(&username, &ip, &device);
        return json_error(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts. Try again later.",
        );
    }
    let found = db.user_by_username(&username);
    let valid = found
        .as_ref()
        .map(|u| !u.blocked && security::verify_password(&payload.password, &u.password_hash))
        .unwrap_or(false);
    if !valid {
        if let Some(bucket) = db.login_buckets.get_mut(&ip) {
            bucket.attempts += 1;
        }
        db.add_failed(&username, &ip, &device);
        if let Some(user) = found {
            if let Some(stored) = db.users.get_mut(&user.id) {
                stored.failed_login_count = stored.failed_login_count.saturating_add(1);
            }
        }
        return json_error(StatusCode::UNAUTHORIZED, "Invalid username or password");
    }
    let user = found.expect("valid login has user");
    db.login_buckets.remove(&ip);
    db.sessions.retain(|_, session| session.user_id != user.id);
    let session_id = security::random_token(32);
    let csrf_token = security::random_token(24);
    db.sessions.insert(
        session_id.clone(),
        store::Session {
            user_id: user.id.clone(),
            created_at: now,
            last_seen: now,
            csrf_token,
        },
    );
    if let Some(stored) = db.users.get_mut(&user.id) {
        stored.failed_login_count = 0;
        stored.last_login = Some(now);
    }
    db.add_activity(&user.username, "login", "Successful sign in", &ip);
    db.add_audit(
        &user.username,
        "session.created",
        "Authenticated session created",
        &ip,
    );
    let mut response =
        Json(json!({"ok": true, "redirect": "/home", "message": "Signed in"})).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&security::session_cookie(
            &session_id,
            state.config.session_absolute_secs,
            state.config.cookie_secure,
        ))
        .unwrap(),
    );
    response
}

pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let token = security::cookie_value(&headers, "vvc_session");
    let Some(token) = token else {
        return (
            StatusCode::NO_CONTENT,
            [(
                header::SET_COOKIE,
                security::expired_session_cookie(state.config.cookie_secure),
            )],
        )
            .into_response();
    };
    let Some(ctx) = auth_context(&state, &headers).await else {
        return (
            StatusCode::NO_CONTENT,
            [(
                header::SET_COOKIE,
                security::expired_session_cookie(state.config.cookie_secure),
            )],
        )
            .into_response();
    };
    if !csrf_valid(&headers, &ctx) {
        return json_error(StatusCode::FORBIDDEN, "CSRF validation failed");
    }
    let ip = security::client_ip(&headers);
    let mut db = state.pub_store.write().await;
    db.sessions.remove(&token);
    db.add_activity(&ctx.user.username, "logout", "Session revoked", &ip);
    db.add_audit(
        &ctx.user.username,
        "session.revoked",
        "User logged out",
        &ip,
    );
    (
        StatusCode::NO_CONTENT,
        [(
            header::SET_COOKIE,
            security::expired_session_cookie(state.config.cookie_secure),
        )],
    )
        .into_response()
}

pub async fn home_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    protected_page(&state, &headers, "home.read", HOME_HTML, "Home").await
}
pub async fn about_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    protected_page(&state, &headers, "about.read", ABOUT_HTML, "About").await
}
pub async fn admin_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(ctx) = auth_context(&state, &headers).await {
        if !has_permission(&ctx.user, "admin.dashboard.read") {
            return not_found().await;
        }
    }
    protected_page(
        &state,
        &headers,
        "admin.dashboard.read",
        ADMIN_HTML,
        "Admin",
    )
    .await
}
pub async fn home_css(State(state): State<AppState>, headers: HeaderMap) -> Response {
    protected_asset(
        &state,
        &headers,
        "home.read",
        "text/css; charset=utf-8",
        HOME_CSS,
    )
    .await
}
pub async fn home_js(State(state): State<AppState>, headers: HeaderMap) -> Response {
    protected_asset(
        &state,
        &headers,
        "home.read",
        "text/javascript; charset=utf-8",
        HOME_JS,
    )
    .await
}
pub async fn about_css(State(state): State<AppState>, headers: HeaderMap) -> Response {
    protected_asset(
        &state,
        &headers,
        "about.read",
        "text/css; charset=utf-8",
        ABOUT_CSS,
    )
    .await
}
pub async fn about_js(State(state): State<AppState>, headers: HeaderMap) -> Response {
    protected_asset(
        &state,
        &headers,
        "about.read",
        "text/javascript; charset=utf-8",
        ABOUT_JS,
    )
    .await
}
pub async fn admin_css(State(state): State<AppState>, headers: HeaderMap) -> Response {
    protected_asset(
        &state,
        &headers,
        "admin.dashboard.read",
        "text/css; charset=utf-8",
        ADMIN_CSS,
    )
    .await
}
pub async fn admin_js(State(state): State<AppState>, headers: HeaderMap) -> Response {
    protected_asset(
        &state,
        &headers,
        "admin.dashboard.read",
        "text/javascript; charset=utf-8",
        ADMIN_JS,
    )
    .await
}
pub async fn admin_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(path): Path<String>,
) -> Response {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains("..")
        || path.contains('\\')
        || path.chars().any(|c| c.is_control())
    {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    let Some(file) = ADMIN_DIR.get_file(&path) else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };
    let Some(ctx) = auth_context(&state, &headers).await else {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    };
    if !has_permission(&ctx.user, "admin.dashboard.read") {
        return safe_forbidden_page();
    }
    let content_type = match file.path().extension().and_then(|x| x.to_str()) {
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("webp") => "image/webp",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "private, no-store")
        .body(Body::from(file.contents().to_vec()))
        .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response())
}

fn project_root() -> PathBuf {
    if let Ok(value) = std::env::var("VVC_PROJECT_DIR") {
        return PathBuf::from(value);
    }
    let container_root = PathBuf::from("/app/project");
    if container_root.is_dir() {
        container_root
    } else {
        PathBuf::from("backend/project")
    }
}

fn safe_segment(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

fn safe_relative(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value.contains('\0')
        && !value.chars().any(|c| c.is_control())
        && value.split('/').all(|part| {
            safe_segment(part)
                || part.ends_with(".js")
                || part.ends_with(".css")
                || part.ends_with(".html")
        })
        && !value
            .split('/')
            .any(|part| part == "." || part == ".." || part.is_empty())
}

fn dynamic_content_type(path: &FsPath) -> Option<&'static str> {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("html") => Some("text/html; charset=utf-8"),
        Some("css") => Some("text/css; charset=utf-8"),
        Some("js") => Some("text/javascript; charset=utf-8"),
        _ => None,
    }
}

async fn read_project_file(slug: &str, relative: &str) -> Option<(Vec<u8>, &'static str)> {
    if !safe_segment(slug) || !safe_relative(relative) {
        return None;
    }
    let base = project_root().join(slug);
    let candidate = base.join(relative);
    let base_canonical = tokio::fs::canonicalize(&base).await.ok()?;
    let candidate_canonical = tokio::fs::canonicalize(&candidate).await.ok()?;
    if !candidate_canonical.starts_with(&base_canonical) {
        return None;
    }
    let content_type = dynamic_content_type(&candidate_canonical)?;
    Some((
        tokio::fs::read(candidate_canonical).await.ok()?,
        content_type,
    ))
}

pub async fn dynamic_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request<Body>,
) -> Response {
    if request.method() != axum::http::Method::GET {
        return not_found().await;
    }
    let path = request.uri().path().trim_matches('/');
    if let Some(asset_path) = path.strip_prefix("assets/") {
        let mut parts = asset_path.splitn(2, '/');
        let Some(slug) = parts.next() else {
            return not_found().await;
        };
        let Some(relative) = parts.next() else {
            return not_found().await;
        };
        let Some((content, content_type)) = read_project_file(slug, relative).await else {
            return not_found().await;
        };
        if auth_context(&state, &headers).await.is_none() {
            return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
        }
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, content_type)
            .header(header::CACHE_CONTROL, "private, no-store")
            .body(Body::from(content))
            .unwrap_or_else(|_| {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
            });
    }
    if path.is_empty() || path.contains('/') || !safe_segment(path) {
        return not_found().await;
    }
    let Some((content, _)) = read_project_file(path, "index.html").await else {
        return not_found().await;
    };
    let Some(ctx) = auth_context(&state, &headers).await else {
        return Redirect::temporary("/login").into_response();
    };
    let page = path.to_string();
    let ip = security::client_ip(&headers);
    let device = security::device(&headers);
    let mut db = state.pub_store.write().await;
    db.add_view(&page, &ctx.user.username, &ip, &device);
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "private, no-store")
        .body(Body::from(content))
        .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response())
}

async fn protected_page(
    state: &AppState,
    headers: &HeaderMap,
    permission: &str,
    html: &'static str,
    page: &str,
) -> Response {
    let Some(ctx) = auth_context(state, headers).await else {
        return Redirect::temporary("/login").into_response();
    };
    if !has_permission(&ctx.user, permission) {
        return safe_forbidden_page();
    }
    let ip = security::client_ip(headers);
    let device = security::device(headers);
    let mut db = state.pub_store.write().await;
    db.add_view(page, &ctx.user.username, &ip, &device);
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "private, no-store"),
        ],
        html,
    )
        .into_response()
}
async fn protected_asset(
    state: &AppState,
    headers: &HeaderMap,
    permission: &str,
    content_type: &str,
    body: &'static str,
) -> Response {
    let Some(ctx) = auth_context(state, headers).await else {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    };
    if !has_permission(&ctx.user, permission) {
        return safe_forbidden_page();
    }
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "private, no-store"),
        ],
        body,
    )
        .into_response()
}

pub async fn me(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(ctx) = api_context(&state, &headers, None).await else {
        return json_error(StatusCode::UNAUTHORIZED, "Authentication required");
    };
    let mut permissions: Vec<String> = store::permissions_for(&ctx.user).into_iter().collect();
    permissions.sort();
    Json(MeResponse {
        id: ctx.user.id,
        username: ctx.user.username,
        email: ctx.user.email,
        role: ctx.user.role.as_str().into(),
        role_label: ctx.user.role.label().into(),
        permissions,
        csrf_token: ctx.csrf_token,
    })
    .into_response()
}

pub async fn admin_stats(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Response {
    let Some(ctx) = api_context(&state, &headers, Some("admin.dashboard.read")).await else {
        return json_error(StatusCode::FORBIDDEN, "Permission required");
    };
    let db = state.pub_store.read().await;
    let start = range_start(query.range.as_deref());
    let today = range_start(Some("today"));
    let seven = range_start(Some("7d"));
    let total_users = db.users.len();
    let blocked_users = db.users.values().filter(|u| u.blocked).count();
    let today_views = db
        .views
        .iter()
        .filter(|v| v.timestamp >= today.unwrap_or(0))
        .count();
    let seven_day_views = db
        .views
        .iter()
        .filter(|v| v.timestamp >= seven.unwrap_or(0))
        .count();
    let today_spam = db
        .spam
        .iter()
        .filter(|item| item.timestamp >= today.unwrap_or(0))
        .count();
    let recent_activity: Vec<_> = db
        .activity
        .iter()
        .rev()
        .filter(|a| start.map(|s| a.timestamp >= s).unwrap_or(true))
        .take(8)
        .cloned()
        .collect();
    drop(ctx);
    Json(json!({"total_users": total_users, "today_views": today_views, "seven_day_views": seven_day_views, "blocked_users": blocked_users, "today_spam": today_spam, "recent_activity": recent_activity})).into_response()
}

pub async fn admin_activity(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Response {
    if api_context(&state, &headers, Some("admin.activity.read"))
        .await
        .is_none()
    {
        return json_error(StatusCode::FORBIDDEN, "Permission required");
    }
    let db = state.pub_store.read().await;
    let start = range_start(query.range.as_deref());
    let search = query.search.as_deref().unwrap_or("").to_lowercase();
    let items: Vec<_> = db
        .activity
        .iter()
        .rev()
        .filter(|item| start.map(|s| item.timestamp >= s).unwrap_or(true))
        .filter(|item| {
            search.is_empty()
                || format!("{} {} {}", item.user, item.action, item.details)
                    .to_lowercase()
                    .contains(&search)
        })
        .cloned()
        .collect();
    paged_response(items, &query)
}

pub async fn admin_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Response {
    if api_context(&state, &headers, Some("admin.users.read"))
        .await
        .is_none()
    {
        return json_error(StatusCode::FORBIDDEN, "Permission required");
    }
    let db = state.pub_store.read().await;
    let search = query.search.as_deref().unwrap_or("").to_lowercase();
    let items: Vec<UserSummary> = db
        .users
        .values()
        .filter(|u| {
            search.is_empty()
                || format!("{} {} {}", u.username, u.email, u.role.label())
                    .to_lowercase()
                    .contains(&search)
        })
        .map(summary)
        .collect();
    paged_response(items, &query)
}

pub async fn admin_create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateUserPayload>,
) -> Response {
    let Some(ctx) = api_context(&state, &headers, Some("admin.users.create")).await else {
        return json_error(StatusCode::FORBIDDEN, "Permission required");
    };
    let username = payload.username.trim().to_string();
    let email = payload.email.trim().to_string();
    if !valid_username(&username)
        || !valid_email(&email)
        || payload.password.len() < 12
        || payload.password.len() > 256
    {
        return json_error(StatusCode::BAD_REQUEST, "Invalid user fields");
    }
    let role = match parse_role(&payload.role) {
        Some(r) => r,
        None => return json_error(StatusCode::BAD_REQUEST, "Unsupported role"),
    };
    if role == Role::SuperAdmin && ctx.user.role != Role::SuperAdmin {
        return json_error(
            StatusCode::FORBIDDEN,
            "Only Super Admin can create Super Admin accounts",
        );
    }
    let mut db = state.pub_store.write().await;
    if db
        .users
        .values()
        .any(|u| u.username.eq_ignore_ascii_case(&username) || u.email.eq_ignore_ascii_case(&email))
    {
        return json_error(StatusCode::CONFLICT, "Username or email already exists");
    }
    let permissions = delegated_permissions(&ctx.user, &role);
    let id = store::new_id();
    let password_hash = match security::hash_password(&payload.password) {
        Ok(v) => v,
        Err(_) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to create account",
            )
        }
    };
    let user = User {
        id: id.clone(),
        username: username.clone(),
        email,
        password_hash,
        role: role.clone(),
        delegated_permissions: permissions,
        blocked: false,
        failed_login_count: 0,
        last_login: None,
        created_at: store::now(),
    };
    db.users.insert(id, user);
    db.add_activity(
        &ctx.user.username,
        "user.created",
        &format!("Created {username} as {}", role.label()),
        &security::client_ip(&headers),
    );
    db.add_audit(
        &ctx.user.username,
        "user.created",
        &format!("Created account {username}"),
        &security::client_ip(&headers),
    );
    (StatusCode::CREATED, Json(json!({"ok": true}))).into_response()
}

pub async fn admin_update_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<RolePayload>,
) -> Response {
    let Some(ctx) = api_context(&state, &headers, Some("admin.users.update_role")).await else {
        return json_error(StatusCode::FORBIDDEN, "Permission required");
    };
    if !csrf_valid(&headers, &ctx) {
        return json_error(StatusCode::FORBIDDEN, "CSRF validation failed");
    }
    let role = match parse_role(&payload.role) {
        Some(r) => r,
        None => return json_error(StatusCode::BAD_REQUEST, "Unsupported role"),
    };
    if role == Role::SuperAdmin && ctx.user.role != Role::SuperAdmin {
        return json_error(
            StatusCode::FORBIDDEN,
            "Only Super Admin can assign Super Admin",
        );
    }
    let mut db = state.pub_store.write().await;
    let Some(target) = db.users.get(&id).cloned() else {
        return json_error(StatusCode::NOT_FOUND, "User not found");
    };
    if target.role == Role::SuperAdmin
        && role != Role::SuperAdmin
        && !target.blocked
        && db.active_super_admins() <= 1
    {
        return json_error(
            StatusCode::CONFLICT,
            "The last active Super Admin cannot be demoted",
        );
    }
    if let Some(stored) = db.users.get_mut(&id) {
        stored.role = role.clone();
        stored.delegated_permissions = delegated_permissions(&ctx.user, &role);
    }
    db.sessions.retain(|_, s| s.user_id != id);
    db.add_activity(
        &ctx.user.username,
        "user.role_changed",
        &format!("{} -> {}", target.role.label(), role.label()),
        &security::client_ip(&headers),
    );
    db.add_audit(
        &ctx.user.username,
        "user.role_changed",
        &format!("Changed {} to {}", target.username, role.label()),
        &security::client_ip(&headers),
    );
    Json(json!({"ok": true})).into_response()
}

pub async fn admin_block_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    change_block(&state, &headers, &id, true).await
}
pub async fn admin_unblock_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    change_block(&state, &headers, &id, false).await
}
async fn change_block(state: &AppState, headers: &HeaderMap, id: &str, blocked: bool) -> Response {
    let Some(ctx) = api_context(state, headers, Some("admin.users.block")).await else {
        return json_error(StatusCode::FORBIDDEN, "Permission required");
    };
    if !csrf_valid(headers, &ctx) {
        return json_error(StatusCode::FORBIDDEN, "CSRF validation failed");
    }
    let mut db = state.pub_store.write().await;
    let Some(target) = db.users.get(id).cloned() else {
        return json_error(StatusCode::NOT_FOUND, "User not found");
    };
    if target.id == ctx.user.id {
        return json_error(
            StatusCode::CONFLICT,
            "You cannot change your own account status",
        );
    }
    if blocked
        && target.role == Role::SuperAdmin
        && !target.blocked
        && db.active_super_admins() <= 1
    {
        return json_error(
            StatusCode::CONFLICT,
            "The last active Super Admin cannot be blocked",
        );
    }
    if let Some(stored) = db.users.get_mut(id) {
        stored.blocked = blocked;
    }
    if blocked {
        db.sessions.retain(|_, s| s.user_id != id);
    }
    let action = if blocked {
        "user.blocked"
    } else {
        "user.unblocked"
    };
    db.add_activity(
        &ctx.user.username,
        action,
        &target.username,
        &security::client_ip(headers),
    );
    db.add_audit(
        &ctx.user.username,
        action,
        &target.username,
        &security::client_ip(headers),
    );
    Json(json!({"ok": true})).into_response()
}

pub async fn admin_delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let Some(ctx) = api_context(&state, &headers, Some("admin.users.delete")).await else {
        return json_error(StatusCode::FORBIDDEN, "Permission required");
    };
    if !csrf_valid(&headers, &ctx) {
        return json_error(StatusCode::FORBIDDEN, "CSRF validation failed");
    }
    let mut db = state.pub_store.write().await;
    let Some(target) = db.users.get(&id).cloned() else {
        return json_error(StatusCode::NOT_FOUND, "User not found");
    };
    if target.id == ctx.user.id {
        return json_error(StatusCode::CONFLICT, "You cannot delete your own account");
    }
    if target.role == Role::SuperAdmin && !target.blocked && db.active_super_admins() <= 1 {
        return json_error(
            StatusCode::CONFLICT,
            "The last active Super Admin cannot be deleted",
        );
    }
    db.users.remove(&id);
    db.sessions.retain(|_, s| s.user_id != id);
    db.add_activity(
        &ctx.user.username,
        "user.deleted",
        &target.username,
        &security::client_ip(&headers),
    );
    db.add_audit(
        &ctx.user.username,
        "user.deleted",
        &target.username,
        &security::client_ip(&headers),
    );
    Json(json!({"ok": true})).into_response()
}

pub async fn admin_roles(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if api_context(&state, &headers, Some("admin.users.read"))
        .await
        .is_none()
    {
        return json_error(StatusCode::FORBIDDEN, "Permission required");
    }
    Json(json!({"roles":[{"id":"super_admin","label":"Super Admin"},{"id":"admin","label":"Admin"},{"id":"viewer","label":"User"}],"permissions": store::ALL_PERMISSIONS})).into_response()
}

pub async fn admin_views(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Response {
    if api_context(&state, &headers, Some("admin.views.read"))
        .await
        .is_none()
    {
        return json_error(StatusCode::FORBIDDEN, "Permission required");
    }
    let db = state.pub_store.read().await;
    let start = range_start(query.range.as_deref());
    let page_name = query.page_name.as_deref().unwrap_or("").to_lowercase();
    let items: Vec<ViewLog> = db
        .views
        .iter()
        .rev()
        .filter(|v| start.map(|s| v.timestamp >= s).unwrap_or(true))
        .filter(|v| page_name.is_empty() || v.page.to_lowercase() == page_name)
        .cloned()
        .collect();
    paged_response(items, &query)
}

pub async fn admin_failed_logins(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Response {
    if api_context(&state, &headers, Some("admin.failed_logins.read"))
        .await
        .is_none()
    {
        return json_error(StatusCode::FORBIDDEN, "Permission required");
    }
    let db = state.pub_store.read().await;
    let start = range_start(query.range.as_deref());
    let items: Vec<FailedLogin> = db
        .failed_logins
        .iter()
        .rev()
        .filter(|v| start.map(|s| v.timestamp >= s).unwrap_or(true))
        .cloned()
        .collect();
    paged_response(items, &query)
}

pub async fn admin_spam(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Response {
    if api_context(&state, &headers, Some("admin.spam.read"))
        .await
        .is_none()
    {
        return json_error(StatusCode::FORBIDDEN, "Permission required");
    }
    let db = state.pub_store.read().await;
    let start = range_start(query.range.as_deref());
    let search = query.search.as_deref().unwrap_or("").to_lowercase();
    let items: Vec<_> = db
        .spam
        .iter()
        .rev()
        .filter(|item| start.map(|s| item.timestamp >= s).unwrap_or(true))
        .filter(|item| {
            search.is_empty()
                || format!(
                    "{} {} {} {} {} {}",
                    item.username,
                    item.ip,
                    item.device_fingerprint,
                    item.device_model,
                    item.route,
                    item.method
                )
                .to_lowercase()
                .contains(&search)
        })
        .cloned()
        .collect();
    paged_response(items, &query)
}

pub async fn admin_audit_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Response {
    if api_context(&state, &headers, Some("admin.audit_logs.read"))
        .await
        .is_none()
    {
        return json_error(StatusCode::FORBIDDEN, "Permission required");
    }
    let db = state.pub_store.read().await;
    let start = range_start(query.range.as_deref());
    let items: Vec<AuditLog> = db
        .audits
        .iter()
        .rev()
        .filter(|item| start.map(|s| item.timestamp >= s).unwrap_or(true))
        .cloned()
        .collect();
    paged_response(items, &query)
}

pub async fn admin_clear_views(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(range): Path<String>,
) -> Response {
    clear_operational(&state, &headers, &range, "views").await
}
pub async fn admin_clear_activity(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(range): Path<String>,
) -> Response {
    clear_operational(&state, &headers, &range, "activity").await
}
pub async fn admin_clear_failed(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(range): Path<String>,
) -> Response {
    clear_operational(&state, &headers, &range, "failed").await
}
pub async fn admin_clear_spam(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(range): Path<String>,
) -> Response {
    clear_operational(&state, &headers, &range, "spam").await
}
async fn clear_operational(
    state: &AppState,
    headers: &HeaderMap,
    range: &str,
    kind: &str,
) -> Response {
    let permission = match kind {
        "views" => "admin.views.clear",
        "activity" => "admin.activity.clear",
        "spam" => "admin.spam.clear",
        _ => "admin.failed_logins.clear",
    };
    let Some(ctx) = api_context(state, headers, Some(permission)).await else {
        return json_error(StatusCode::FORBIDDEN, "Permission required");
    };
    if !csrf_valid(headers, &ctx) {
        return json_error(StatusCode::FORBIDDEN, "CSRF validation failed");
    }
    if range_start(Some(range)).is_none() && range != "all" {
        return json_error(StatusCode::BAD_REQUEST, "Invalid date range");
    }
    let start = range_start(Some(range));
    let mut db = state.pub_store.write().await;
    match kind {
        "views" => db
            .views
            .retain(|item| start.map(|s| item.timestamp < s).unwrap_or(false)),
        "activity" => db
            .activity
            .retain(|item| start.map(|s| item.timestamp < s).unwrap_or(false)),
        "spam" => db
            .spam
            .retain(|item| start.map(|s| item.timestamp < s).unwrap_or(false)),
        _ => db
            .failed_logins
            .retain(|item| start.map(|s| item.timestamp < s).unwrap_or(false)),
    }
    db.add_audit(
        &ctx.user.username,
        "operational_logs.cleared",
        &format!("Cleared {kind} for {range}; security audit records retained"),
        &security::client_ip(headers),
    );
    Json(json!({"ok": true, "cleared": kind, "range": range})).into_response()
}

pub async fn gateway_guard(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    if request.uri().path() == "/healthz" {
        return next.run(request).await;
    }
    let route = request.uri().path().to_string();
    let method = request.method().as_str().to_string();
    let headers = request.headers().clone();
    let ip = security::client_ip(&headers);
    let device = security::device(&headers);
    let fingerprint = security::device_fingerprint(&headers);
    let model = security::device_model(&headers);
    if let Some(secret) = &state.config.gateway_secret {
        let supplied = request
            .headers()
            .get("x-vvc-gateway")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !security::constant_time_equal(supplied, secret) {
            let response = (StatusCode::NOT_FOUND, "not found").into_response();
            record_spam(
                &state,
                &headers,
                &ip,
                &fingerprint,
                &model,
                &device,
                &route,
                &method,
                404,
            )
            .await;
            return response;
        }
    }
    let response = next.run(request).await;
    let status = response.status().as_u16();
    record_spam(
        &state,
        &headers,
        &ip,
        &fingerprint,
        &model,
        &device,
        &route,
        &method,
        status,
    )
    .await;
    response
}

#[allow(clippy::too_many_arguments)]
async fn record_spam(
    state: &AppState,
    headers: &HeaderMap,
    ip: &str,
    fingerprint: &str,
    model: &str,
    device: &str,
    route: &str,
    method: &str,
    status: u16,
) {
    let username = {
        let db = state.pub_store.read().await;
        security::cookie_value(headers, "vvc_session")
            .and_then(|token| db.sessions.get(&token))
            .and_then(|session| db.users.get(&session.user_id))
            .map(|user| user.username.clone())
            .unwrap_or_else(|| "anonymous".into())
    };
    let mut db = state.pub_store.write().await;
    db.add_spam(
        &username,
        ip,
        fingerprint,
        model,
        device,
        route,
        method,
        status,
    );
}

pub async fn security_headers(request: Request<axum::body::Body>, next: Next) -> Response {
    let is_admin_page = request.uri().path() == "/admin";
    let is_login_page = request.uri().path() == "/login";
    let dynamic_segment = request.uri().path().trim_matches('/');
    let is_dynamic_page = safe_segment(dynamic_segment)
        && !matches!(
            dynamic_segment,
            "" | "home" | "about" | "admin" | "login" | "health" | "healthz"
        )
        && !dynamic_segment.starts_with("api")
        && !dynamic_segment.starts_with("assets");
    let mut response = next.run(request).await;
    let is_404_page = response.status() == StatusCode::NOT_FOUND;
    let headers = response.headers_mut();
    let csp = if is_admin_page || is_login_page || is_dynamic_page || is_404_page {
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'"
    } else {
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'"
    };
    headers.insert("content-security-policy", HeaderValue::from_static(csp));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    response
}

async fn auth_context(state: &AppState, headers: &HeaderMap) -> Option<AuthContext> {
    let token = security::cookie_value(headers, "vvc_session")?;
    let mut db = state.pub_store.write().await;
    let now = store::now();
    let session = db.sessions.get(&token).cloned()?;
    if now.saturating_sub(session.last_seen) > state.config.session_idle_secs
        || now.saturating_sub(session.created_at) > state.config.session_absolute_secs
    {
        db.sessions.remove(&token);
        return None;
    }
    let user = db.user(&session.user_id)?;
    if user.blocked {
        db.sessions.remove(&token);
        return None;
    }
    if let Some(stored) = db.sessions.get_mut(&token) {
        stored.last_seen = now;
    }
    Some(AuthContext {
        user,
        csrf_token: session.csrf_token,
    })
}
async fn api_context(
    state: &AppState,
    headers: &HeaderMap,
    permission: Option<&str>,
) -> Option<AuthContext> {
    let ctx = auth_context(state, headers).await?;
    if permission
        .map(|p| has_permission(&ctx.user, p))
        .unwrap_or(true)
    {
        Some(ctx)
    } else {
        None
    }
}
fn csrf_valid(headers: &HeaderMap, ctx: &AuthContext) -> bool {
    headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .map(|v| security::constant_time_equal(v, &ctx.csrf_token))
        .unwrap_or(false)
}
fn has_permission(user: &User, permission: &str) -> bool {
    store::permissions_for(user).contains(permission)
}
fn safe_forbidden_page() -> Response {
    (StatusCode::FORBIDDEN, [(header::CONTENT_TYPE, "text/html; charset=utf-8")], "<!doctype html><title>Access denied</title><main style=\"font-family:system-ui;padding:3rem\"><h1>Access denied</h1><p>This workspace permission is not assigned to your account.</p><a href=\"/home\">Return to Home</a></main>").into_response()
}
fn json_error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({"error": message}))).into_response()
}
fn summary(u: &User) -> UserSummary {
    UserSummary {
        id: u.id.clone(),
        username: u.username.clone(),
        email: u.email.clone(),
        role: u.role.as_str().into(),
        role_label: u.role.label().into(),
        blocked: u.blocked,
        failed_login_count: u.failed_login_count,
        last_login: u.last_login,
        created_at: u.created_at,
    }
}
fn paged_response<T: Serialize + Clone>(items: Vec<T>, query: &ListQuery) -> Response {
    let limit = query.limit.unwrap_or(25).clamp(1, 100);
    let page = query.page.unwrap_or(1).clamp(1, 10_000);
    let total = items.len();
    let start = (page - 1) * limit;
    let slice = items.into_iter().skip(start).take(limit).collect();
    Json(Paged {
        items: slice,
        total,
        page,
        limit,
    })
    .into_response()
}
fn range_start(range: Option<&str>) -> Option<u64> {
    let now = store::now();
    match range.unwrap_or("all").to_lowercase().as_str() {
        "today" => Some(now - (now % 86_400)),
        "7d" | "7days" | "7-days" => Some(now.saturating_sub(7 * 86_400)),
        "30d" | "30days" | "30-days" => Some(now.saturating_sub(30 * 86_400)),
        "all" | "" => None,
        _ => None,
    }
}
fn valid_username(value: &str) -> bool {
    (3..=64).contains(&value.len())
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}
fn valid_email(value: &str) -> bool {
    value.len() <= 254
        && value
            .split_once('@')
            .map(|(a, b)| {
                !a.is_empty() && b.contains('.') && !b.starts_with('.') && !b.ends_with('.')
            })
            .unwrap_or(false)
}
fn parse_role(value: &str) -> Option<Role> {
    match value {
        "super_admin" => Some(Role::SuperAdmin),
        "admin" => Some(Role::Admin),
        "viewer" => Some(Role::User),
        _ => None,
    }
}
fn delegated_permissions(actor: &User, role: &Role) -> HashSet<String> {
    if role == &Role::SuperAdmin {
        return store::ALL_PERMISSIONS
            .iter()
            .map(|s| (*s).to_string())
            .collect();
    }
    let actor_permissions = store::permissions_for(actor);
    let allowed: HashSet<String> = match role {
        Role::Admin => store::ALL_PERMISSIONS
            .iter()
            .filter(|p| **p != "admin.audit_logs.read")
            .map(|s| (*s).to_string())
            .collect(),
        Role::User => ["home.read", "about.read"]
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        Role::SuperAdmin => HashSet::new(),
    };
    allowed.intersection(&actor_permissions).cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn password_hashes_verify_without_plaintext() {
        let hash = security::hash_password("correct horse battery staple").unwrap();
        assert_ne!(hash, "correct horse battery staple");
        assert!(security::verify_password(
            "correct horse battery staple",
            &hash
        ));
        assert!(!security::verify_password("wrong", &hash));
    }
    #[test]
    fn ranges_are_bounded() {
        assert!(range_start(Some("today")).is_some());
        assert!(range_start(Some("7d")).is_some());
        assert!(range_start(Some("30d")).is_some());
        assert!(range_start(Some("all")).is_none());
    }
    #[test]
    fn usernames_and_emails_are_validated() {
        assert!(valid_username("ops.viewer"));
        assert!(!valid_username("x"));
        assert!(valid_email("ops@example.com"));
        assert!(!valid_email("not-an-email"));
    }
}

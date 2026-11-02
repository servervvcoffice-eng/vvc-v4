mod config;
mod handlers;
mod security;
mod store;

use axum::{
    extract::DefaultBodyLimit,
    middleware,
    routing::{delete, get, post, put},
    Router,
};
use config::Config;
use std::sync::Arc;
use std::time::Duration;
use store::{AppState, Store};
use tokio::net::TcpListener;
use tower_http::{timeout::TimeoutLayer, trace::TraceLayer};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let config = Config::from_env();
    if config.is_production() {
        tracing::error!("production startup refused: this build uses the Preview in-memory repository; wire the durable Supabase/Redis adapters, gateway secret, and one-time bootstrap flow before production");
        std::process::exit(78);
    }
    let state = AppState {
        pub_store: Arc::new(tokio::sync::RwLock::new(Store::seeded(&config))),
        config: config.clone(),
    };
    tracing::info!(environment = %config.app_env, "AegisCore configuration loaded");
    let app = Router::new()
        .route("/", get(handlers::root))
        .route("/healthz", get(handlers::healthz))
        .route("/health", get(handlers::healthz))
        .route("/manus-routes.json", get(handlers::routes_manifest))
        .route("/login", get(handlers::login_page).post(handlers::login))
        .route("/logout", post(handlers::logout))
        .route("/home", get(handlers::home_page))
        .route("/about", get(handlers::about_page))
        .route("/admin", get(handlers::admin_page))
        .route("/assets/login.css", get(handlers::login_css))
        .route("/assets/login.js", get(handlers::login_js))
        .route("/assets/home.css", get(handlers::home_css))
        .route("/assets/home.js", get(handlers::home_js))
        .route("/assets/about.css", get(handlers::about_css))
        .route("/assets/about.js", get(handlers::about_js))
        .route("/assets/admin.css", get(handlers::admin_css))
        .route("/assets/admin.js", get(handlers::admin_js))
        .route("/assets/admin/*path", get(handlers::admin_file))
        .route("/api/me", get(handlers::me))
        .route("/api/admin/stats", get(handlers::admin_stats))
        .route("/api/admin/activity", get(handlers::admin_activity))
        .route(
            "/api/admin/users",
            get(handlers::admin_users).post(handlers::admin_create_user),
        )
        .route(
            "/api/admin/users/:id/role",
            put(handlers::admin_update_role),
        )
        .route(
            "/api/admin/users/:id/block",
            post(handlers::admin_block_user),
        )
        .route(
            "/api/admin/users/:id/unblock",
            post(handlers::admin_unblock_user),
        )
        .route("/api/admin/users/:id", delete(handlers::admin_delete_user))
        .route("/api/admin/roles", get(handlers::admin_roles))
        .route("/api/admin/views", get(handlers::admin_views))
        .route(
            "/api/admin/failed-logins",
            get(handlers::admin_failed_logins),
        )
        .route("/api/admin/spam", get(handlers::admin_spam))
        .route("/api/admin/audit-logs", get(handlers::admin_audit_logs))
        .route(
            "/api/admin/clear/views/:range",
            delete(handlers::admin_clear_views),
        )
        .route(
            "/api/admin/clear/activity/:range",
            delete(handlers::admin_clear_activity),
        )
        .route(
            "/api/admin/clear/failed/:range",
            delete(handlers::admin_clear_failed),
        )
        .route(
            "/api/admin/clear/spam/:range",
            delete(handlers::admin_clear_spam),
        )
        .fallback(handlers::dynamic_route)
        .with_state(state.clone())
        .layer(DefaultBodyLimit::max(config.max_body_bytes))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            handlers::gateway_guard,
        ))
        .layer(middleware::from_fn(handlers::security_headers))
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::new(Duration::from_secs(15)));
    let listener = TcpListener::bind(config.bind_addr)
        .await
        .expect("bind server");
    tracing::info!(address = %config.bind_addr, "AegisCore listening");
    axum::serve(listener, app).await.expect("server failure");
}

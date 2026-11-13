mod config;
mod handlers;
mod rate_limit;
mod security;
mod store;

use axum::http::{header, HeaderName, HeaderValue, Method};
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
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(error) => {
            tracing::error!(error = %error.0, "invalid runtime configuration");
            std::process::exit(78);
        }
    };
    let login_limiter = match rate_limit::LoginRateLimiter::connect(
        config.redis_url.as_deref(),
        config.is_production(),
    )
    .await
    {
        Ok(limiter) => {
            if config.redis_url.is_some() {
                tracing::info!("Redis login rate limiter connected");
            } else {
                tracing::warn!(
                    "REDIS_URL is not configured; using process-local preview login limiter"
                );
            }
            limiter
        }
        Err(error) => {
            tracing::error!(%error, "Redis login rate limiter startup check failed");
            std::process::exit(78);
        }
    };
    // Per-account login throttle and the global throttle are separate
    // counters from the per-IP login limiter (see rate_limit.rs).
    let account_limiter = match rate_limit::LoginRateLimiter::connect(
        config.redis_url.as_deref(),
        config.is_production(),
    )
    .await
    {
        Ok(limiter) => limiter,
        Err(error) => {
            tracing::error!(%error, "Account rate limiter startup check failed");
            std::process::exit(78);
        }
    };
    let global_limiter = match rate_limit::LoginRateLimiter::connect_global(
        config.redis_url.as_deref(),
        config.is_production(),
    )
    .await
    {
        Ok(limiter) => limiter,
        Err(error) => {
            tracing::error!(%error, "Global rate limiter startup check failed");
            std::process::exit(78);
        }
    };
    if config.gateway_secret.is_none() {
        tracing::warn!(
            "VVC_GATEWAY_SECRET is not configured; direct-origin requests are not gateway-checked (local development only)"
        );
    }
    let persistence = if let Some(database_url) = &config.database_url {
        match store::Persistence::connect(database_url).await {
            Ok(persistence) => {
                tracing::info!("Supabase PostgreSQL persistence connected");
                Some(Arc::new(persistence))
            }
            Err(error) => {
                tracing::error!(%error, "DATABASE_URL was provided but Supabase PostgreSQL connection failed");
                std::process::exit(78);
            }
        }
    } else {
        tracing::warn!("DATABASE_URL is not configured; using process-local preview store");
        None
    };
    let mut initial_store = if config.is_production() {
        Store::empty()
    } else {
        Store::seeded(&config)
    };
    if let Some(persistence) = &persistence {
        if config.is_production() {
            let email = config
                .bootstrap_email
                .as_deref()
                .expect("production bootstrap email validated");
            let password_hash = match security::hash_password(&config.dev_password) {
                Ok(hash) => hash,
                Err(error) => {
                    tracing::error!(%error, "Could not hash bootstrap password");
                    std::process::exit(78);
                }
            };
            match persistence
                .bootstrap_superadmin(email, &password_hash)
                .await
            {
                Ok(true) => tracing::info!("Created the one-time bootstrap Super Admin"),
                Ok(false) => {
                    tracing::info!("Existing PostgreSQL users found; bootstrap permanently skipped")
                }
                Err(error) => {
                    tracing::error!(%error, "Could not complete PostgreSQL bootstrap");
                    std::process::exit(78);
                }
            }
        }
        match persistence.load_users(&mut initial_store).await {
            Ok(count) if count > 0 => tracing::info!(users = count, "Loaded users from Supabase"),
            Ok(_) => {
                tracing::error!("Supabase users table is empty after bootstrap");
                std::process::exit(78);
            }
            Err(error) => {
                tracing::error!(%error, "Could not load users from Supabase");
                std::process::exit(78);
            }
        }
    }
    let state = AppState {
        pub_store: Arc::new(tokio::sync::RwLock::new(initial_store)),
        config: config.clone(),
        persistence,
        login_limiter,
        account_limiter,
        global_limiter,
    };
    // Retention job: operational logs older than LOG_RETENTION_DAYS are
    // deleted (database + in-memory). Security audit logs are never
    // deleted by this job.
    {
        let retention_state = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(6 * 60 * 60));
            loop {
                interval.tick().await;
                let cutoff =
                    store::now().saturating_sub(retention_state.config.log_retention_days * 86_400);
                if let Some(persistence) = &retention_state.persistence {
                    if let Err(error) = persistence.delete_old_logs(cutoff).await {
                        tracing::error!(%error, "operational log retention cleanup failed");
                    }
                }
                retention_state
                    .pub_store
                    .write()
                    .await
                    .prune_old_logs(cutoff);
            }
        });
    }
    tracing::info!(environment = %config.app_env, "VVC Office configuration loaded");
    let app = Router::new()
        .route("/", get(handlers::root))
        .route("/healthz", get(handlers::healthz))
        .route("/readyz", get(handlers::readyz))
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
        .route("/api/me/password", post(handlers::change_password))
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
        .layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(
                    std::iter::once(config::ALLOWED_ORIGIN)
                        .chain(config.allowed_origins.iter().map(String::as_str))
                        .map(HeaderValue::from_str)
                        .collect::<Result<Vec<_>, _>>()
                        .expect("allowed origins must be valid header values"),
                ))
                .allow_credentials(true)
                .allow_methods([
                    Method::GET,
                    Method::POST,
                    Method::PUT,
                    Method::DELETE,
                    Method::OPTIONS,
                ])
                .allow_headers([
                    header::CONTENT_TYPE,
                    HeaderName::from_static("x-csrf-token"),
                    HeaderName::from_static("x-vvc-gateway"),
                ]),
        )
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
    tracing::info!(address = %config.bind_addr, "VVC Office listening");
    axum::serve(listener, app).await.expect("server failure");
}

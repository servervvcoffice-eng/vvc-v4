-- Production persistence hardening: keep token lookup and retention/query paths indexed.
create index if not exists sessions_expires_idx on sessions(expires_at);
create index if not exists sessions_user_expires_idx on sessions(user_id, expires_at);
create index if not exists login_attempts_username_created_idx on login_attempts(attempted_username, created_at);
create index if not exists audit_logs_actor_created_idx on audit_logs(actor_user_id, created_at);
create index if not exists security_events_created_idx on security_events(created_at);

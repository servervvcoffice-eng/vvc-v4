-- least_privilege_role.sql — run ONCE by a database owner, not by the app.
--
-- Creates a dedicated application role for DATABASE_URL instead of
-- connecting as the table owner / service_role (which bypasses RLS and
-- can run DDL). After creating it, set Render's DATABASE_URL to use
-- `vvc_app` with a strong password stored only in Render secrets.
--
--   psql "$DATABASE_URL_OWNER" -v vvc_app_password="'<strong-random-password>'" \
--     -f migrations/least_privilege_role.sql
--
-- Replace <strong-random-password> with a generated secret; never commit it.

do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'vvc_app') then
    execute format('create role vvc_app login password %L', :'vvc_app_password');
  end if;
end $$;

revoke all on all tables in schema public from vvc_app;
revoke all on all sequences in schema public from vvc_app;
revoke create on schema public from vvc_app;

grant select, insert, update, delete on
  users, user_roles, sessions, login_attempts, audit_logs,
  view_logs, activity_logs, spam_logs
  to vvc_app;
grant select on roles, permissions, role_permissions to vvc_app;
grant select, insert, update on workspace_settings to vvc_app;
-- The app never writes to security_events directly in this release; keep
-- it read-only for the app role until a writer is needed.
grant select on security_events to vvc_app;
grant usage, select on all sequences in schema public to vvc_app;

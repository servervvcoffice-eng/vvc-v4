-- 005_security_hardening.sql
--
-- Defense in depth for direct database access:
-- * RLS was already enabled on every table, but with no policies at all.
--   A policy-less table is only safe as long as every connection uses a
--   role that bypasses RLS (owner / service_role). These explicit DENY
--   policies make sure the browser-facing Supabase roles (`anon` and
--   `authenticated`) can read or write nothing, even if an anon key is
--   ever used directly against the database. The trusted backend must
--   keep using its own least-privilege application role (see
--   migrations/least_privilege_role.sql) — never the anon key, and never
--   the service-role key from browser code.
-- * Retention is enforced by the application job (LOG_RETENTION_DAYS,
--   default 90): operational logs older than that are deleted. Audit
--   logs are never deleted by retention.
-- Apply with the same privileged connection used for 001-004.

do $$
declare
  tbl text;
begin
  foreach tbl in array array[
    'users', 'roles', 'permissions', 'user_roles', 'role_permissions',
    'sessions', 'login_attempts', 'audit_logs', 'security_events',
    'workspace_settings', 'view_logs', 'activity_logs', 'spam_logs'
  ] loop
    execute format(
      'drop policy if exists deny_anon on %I; '
      'create policy deny_anon on %I for all to anon using (false) with check (false); '
      'drop policy if exists deny_authenticated on %I; '
      'create policy deny_authenticated on %I for all to authenticated using (false) with check (false);',
      tbl, tbl, tbl, tbl
    );
  end loop;
end $$;

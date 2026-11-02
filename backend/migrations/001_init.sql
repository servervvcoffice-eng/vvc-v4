create extension if not exists pgcrypto;

create table if not exists users (
  id uuid primary key default gen_random_uuid(),
  username text not null unique,
  email text not null unique,
  password_hash text not null,
  blocked boolean not null default false,
  failed_login_count integer not null default 0,
  last_login_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create table if not exists roles (id text primary key, label text not null);
create table if not exists permissions (id text primary key, label text not null);
create table if not exists user_roles (user_id uuid references users(id) on delete cascade, role_id text references roles(id), primary key(user_id, role_id));
create table if not exists role_permissions (role_id text references roles(id) on delete cascade, permission_id text references permissions(id) on delete cascade, primary key(role_id, permission_id));
create table if not exists sessions (id_hash text primary key, user_id uuid references users(id) on delete cascade, csrf_token_hash text not null, created_at timestamptz not null, last_seen_at timestamptz not null, expires_at timestamptz not null);
create index if not exists sessions_user_idx on sessions(user_id);
create table if not exists login_attempts (id uuid primary key default gen_random_uuid(), attempted_username text not null, ip_address inet, device_info text, succeeded boolean not null default false, created_at timestamptz not null default now());
create index if not exists login_attempts_created_idx on login_attempts(created_at);
create table if not exists audit_logs (id uuid primary key default gen_random_uuid(), actor_user_id uuid references users(id) on delete set null, action text not null, details jsonb not null default '{}'::jsonb, ip_address inet, created_at timestamptz not null default now());
create index if not exists audit_logs_created_idx on audit_logs(created_at);
create table if not exists security_events (id uuid primary key default gen_random_uuid(), event_type text not null, details jsonb not null default '{}'::jsonb, created_at timestamptz not null default now());
create table if not exists workspace_settings (key text primary key, value jsonb not null, updated_at timestamptz not null default now());
create table if not exists view_logs (id uuid primary key default gen_random_uuid(), page text not null check(page in ('Home','About','Admin')), user_id uuid references users(id) on delete set null, username_snapshot text not null, ip_address inet, device_info text, created_at timestamptz not null default now());
create index if not exists view_logs_created_idx on view_logs(created_at);
create table if not exists activity_logs (id uuid primary key default gen_random_uuid(), user_id uuid references users(id) on delete set null, username_snapshot text not null, action text not null, details text not null, ip_address inet, created_at timestamptz not null default now());
create index if not exists activity_logs_created_idx on activity_logs(created_at);
create table if not exists spam_logs (id uuid primary key default gen_random_uuid(), username_snapshot text not null, ip_address inet, device_fingerprint text not null, device_model text, device_info text, route text not null, method text not null, status_code integer not null, created_at timestamptz not null default now());
create index if not exists spam_logs_created_idx on spam_logs(created_at);

insert into roles(id,label) values ('super_admin','Super Admin'),('admin','Admin'),('viewer','User') on conflict do nothing;
update roles set label = 'User' where id = 'viewer';
insert into permissions(id,label) values
 ('home.read','Read Home'),('about.read','Read About'),('admin.dashboard.read','Read Admin Dashboard'),('admin.users.read','Read Users'),('admin.users.create','Create Users'),('admin.users.update_role','Update User Roles'),('admin.users.block','Block Users'),('admin.users.delete','Delete Users'),('admin.views.read','Read Views'),('admin.views.clear','Clear Views'),('admin.activity.read','Read Activity'),('admin.activity.clear','Clear Activity'),('admin.failed_logins.read','Read Failed Logins'),('admin.failed_logins.clear','Clear Failed Logins'),('admin.audit_logs.read','Read Audit Logs') on conflict do nothing;
insert into role_permissions(role_id,permission_id) select 'super_admin',id from permissions on conflict do nothing;
insert into role_permissions(role_id,permission_id) select 'admin',id from permissions where id <> 'admin.audit_logs.read' on conflict do nothing;
insert into role_permissions(role_id,permission_id) values ('viewer','home.read'),('viewer','about.read') on conflict do nothing;

-- Security audit logs, security events, accounts, roles, permissions, sessions, and settings have no ordinary clear/delete path.
alter table users enable row level security;
alter table roles enable row level security;
alter table permissions enable row level security;
alter table user_roles enable row level security;
alter table role_permissions enable row level security;
alter table sessions enable row level security;
alter table login_attempts enable row level security;
alter table audit_logs enable row level security;
alter table security_events enable row level security;
alter table workspace_settings enable row level security;
alter table view_logs enable row level security;
alter table activity_logs enable row level security;
alter table spam_logs enable row level security;
-- Do not create browser-facing policies. Expose only least-privilege backend functions or service-role operations from the trusted server.
-- Retain view/activity/failed-login logs only for the documented operational/privacy period.

-- User persistence slice: keep bounded admin listing and role/safeguard queries indexed.
create index if not exists users_created_idx on users(created_at, id);
create index if not exists users_blocked_idx on users(blocked);
create index if not exists user_roles_role_user_idx on user_roles(role_id, user_id);

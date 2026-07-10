-- Roles
INSERT OR IGNORE INTO roles (id, name, description, created_at)
VALUES ('role_admin', 'admin', 'Full access to all resources', '2026-07-10T00:00:00.000Z');

INSERT OR IGNORE INTO roles (id, name, description, created_at)
VALUES ('role_editor', 'editor', 'Can read and update resources', '2026-07-10T00:00:00.000Z');

INSERT OR IGNORE INTO roles (id, name, description, created_at)
VALUES ('role_viewer', 'viewer', 'Read-only access', '2026-07-10T00:00:00.000Z');

-- Permissions: users
INSERT OR IGNORE INTO permissions (id, action, resource, created_at)
VALUES ('perm_users_create', 'create', 'users', '2026-07-10T00:00:00.000Z');

INSERT OR IGNORE INTO permissions (id, action, resource, created_at)
VALUES ('perm_users_read', 'read', 'users', '2026-07-10T00:00:00.000Z');

INSERT OR IGNORE INTO permissions (id, action, resource, created_at)
VALUES ('perm_users_update', 'update', 'users', '2026-07-10T00:00:00.000Z');

INSERT OR IGNORE INTO permissions (id, action, resource, created_at)
VALUES ('perm_users_delete', 'delete', 'users', '2026-07-10T00:00:00.000Z');

-- Permissions: roles
INSERT OR IGNORE INTO permissions (id, action, resource, created_at)
VALUES ('perm_roles_create', 'create', 'roles', '2026-07-10T00:00:00.000Z');

INSERT OR IGNORE INTO permissions (id, action, resource, created_at)
VALUES ('perm_roles_read', 'read', 'roles', '2026-07-10T00:00:00.000Z');

INSERT OR IGNORE INTO permissions (id, action, resource, created_at)
VALUES ('perm_roles_update', 'update', 'roles', '2026-07-10T00:00:00.000Z');

INSERT OR IGNORE INTO permissions (id, action, resource, created_at)
VALUES ('perm_roles_delete', 'delete', 'roles', '2026-07-10T00:00:00.000Z');

-- Admin: all permissions
INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES ('role_admin', 'perm_users_create');
INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES ('role_admin', 'perm_users_read');
INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES ('role_admin', 'perm_users_update');
INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES ('role_admin', 'perm_users_delete');
INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES ('role_admin', 'perm_roles_create');
INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES ('role_admin', 'perm_roles_read');
INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES ('role_admin', 'perm_roles_update');
INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES ('role_admin', 'perm_roles_delete');

-- Editor: read + update
INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES ('role_editor', 'perm_users_read');
INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES ('role_editor', 'perm_users_update');
INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES ('role_editor', 'perm_roles_read');
INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES ('role_editor', 'perm_roles_update');

-- Viewer: read only
INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES ('role_viewer', 'perm_users_read');
INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES ('role_viewer', 'perm_roles_read');

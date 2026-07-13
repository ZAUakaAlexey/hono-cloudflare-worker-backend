import { createApp } from "../app";

export function getTestApp() {
  return createApp();
}

function createMockKV(): KVNamespace {
  const store = new Map<string, { value: string; expireAt?: number }>();
  return {
    get: async (key: string, type?: any) => {
      const entry = store.get(key);
      if (!entry) return null;
      if (entry.expireAt && Date.now() / 1000 > entry.expireAt) {
        store.delete(key);
        return null;
      }
      if (type === "json") return JSON.parse(entry.value);
      return entry.value;
    },
    put: async (key: string, value: string, opts?: any) => {
      const expireAt = opts?.expirationTtl ? Math.floor(Date.now() / 1000) + opts.expirationTtl : undefined;
      store.set(key, { value, expireAt });
    },
    delete: async (key: string) => { store.delete(key); },
    list: async () => ({ keys: [], list_complete: true, cacheStatus: null }),
    getWithMetadata: async () => ({ value: null, metadata: null, cacheStatus: null }),
  } as unknown as KVNamespace;
}

export function createMockEnv(db: D1Database) {
  return {
    DB: db,
    KV: createMockKV(),
    ENVIRONMENT: "test",
  };
}

export async function applyMigrations(db: D1Database) {
  const statements = [
    `CREATE TABLE IF NOT EXISTS permissions (id text PRIMARY KEY NOT NULL, action text NOT NULL, resource text NOT NULL, created_at text NOT NULL)`,
    `CREATE TABLE IF NOT EXISTS role_permissions (role_id text NOT NULL, permission_id text NOT NULL, FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE cascade, FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE cascade)`,
    `CREATE TABLE IF NOT EXISTS roles (id text PRIMARY KEY NOT NULL, name text NOT NULL, description text, created_at text NOT NULL)`,
    `CREATE UNIQUE INDEX IF NOT EXISTS roles_name_unique ON roles (name)`,
    `CREATE TABLE IF NOT EXISTS sessions (id text PRIMARY KEY NOT NULL, user_id text NOT NULL, expires_at integer NOT NULL, created_at text NOT NULL, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE cascade)`,
    `CREATE TABLE IF NOT EXISTS user_roles (user_id text NOT NULL, role_id text NOT NULL, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE cascade, FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE cascade)`,
    `CREATE TABLE IF NOT EXISTS users (id text PRIMARY KEY NOT NULL, email text NOT NULL, password_hash text NOT NULL, name text NOT NULL, is_active integer DEFAULT true NOT NULL, created_at text NOT NULL, updated_at text NOT NULL)`,
    `CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique ON users (email)`,
    `CREATE TABLE IF NOT EXISTS audit_log (id text PRIMARY KEY NOT NULL, user_id text, action text NOT NULL, resource text NOT NULL, resource_id text, detail text, ip text, created_at text NOT NULL)`,
    `CREATE TABLE IF NOT EXISTS login_attempts (id text PRIMARY KEY NOT NULL, email text NOT NULL, success integer NOT NULL, ip text, created_at text NOT NULL)`,
  ];

  for (const sql of statements) {
    await db.exec(sql);
  }
}

export async function applySeed(db: D1Database) {
  const statements = [
    `INSERT OR IGNORE INTO roles (id, name, description, created_at) VALUES ('role_admin', 'admin', 'Full access', '2026-01-01T00:00:00.000Z')`,
    `INSERT OR IGNORE INTO roles (id, name, description, created_at) VALUES ('role_editor', 'editor', 'Read and update', '2026-01-01T00:00:00.000Z')`,
    `INSERT OR IGNORE INTO roles (id, name, description, created_at) VALUES ('role_viewer', 'viewer', 'Read only', '2026-01-01T00:00:00.000Z')`,
    `INSERT OR IGNORE INTO permissions (id, action, resource, created_at) VALUES ('perm_users_create', 'create', 'users', '2026-01-01T00:00:00.000Z')`,
    `INSERT OR IGNORE INTO permissions (id, action, resource, created_at) VALUES ('perm_users_read', 'read', 'users', '2026-01-01T00:00:00.000Z')`,
    `INSERT OR IGNORE INTO permissions (id, action, resource, created_at) VALUES ('perm_users_update', 'update', 'users', '2026-01-01T00:00:00.000Z')`,
    `INSERT OR IGNORE INTO permissions (id, action, resource, created_at) VALUES ('perm_users_delete', 'delete', 'users', '2026-01-01T00:00:00.000Z')`,
    `INSERT OR IGNORE INTO permissions (id, action, resource, created_at) VALUES ('perm_roles_create', 'create', 'roles', '2026-01-01T00:00:00.000Z')`,
    `INSERT OR IGNORE INTO permissions (id, action, resource, created_at) VALUES ('perm_roles_read', 'read', 'roles', '2026-01-01T00:00:00.000Z')`,
    `INSERT OR IGNORE INTO permissions (id, action, resource, created_at) VALUES ('perm_roles_update', 'update', 'roles', '2026-01-01T00:00:00.000Z')`,
    `INSERT OR IGNORE INTO permissions (id, action, resource, created_at) VALUES ('perm_roles_delete', 'delete', 'roles', '2026-01-01T00:00:00.000Z')`,
    `INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES ('role_admin', 'perm_users_create')`,
    `INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES ('role_admin', 'perm_users_read')`,
    `INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES ('role_admin', 'perm_users_update')`,
    `INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES ('role_admin', 'perm_users_delete')`,
    `INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES ('role_admin', 'perm_roles_create')`,
    `INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES ('role_admin', 'perm_roles_read')`,
    `INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES ('role_admin', 'perm_roles_update')`,
    `INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES ('role_admin', 'perm_roles_delete')`,
    `INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES ('role_editor', 'perm_users_read')`,
    `INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES ('role_editor', 'perm_users_update')`,
    `INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES ('role_editor', 'perm_roles_read')`,
    `INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES ('role_editor', 'perm_roles_update')`,
    `INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES ('role_viewer', 'perm_users_read')`,
    `INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES ('role_viewer', 'perm_roles_read')`,
  ];

  for (const sql of statements) {
    await db.exec(sql);
  }
}

export function jsonRequest(path: string, options: RequestInit = {}) {
  return new Request(`http://localhost${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
  });
}

export function getSessionCookie(res: Response): string | null {
  const setCookie = res.headers.get("set-cookie");
  if (!setCookie) return null;
  const match = setCookie.match(/session=([^;]+)/);
  return match ? match[1] : null;
}

export async function registerAdminUser(
  app: ReturnType<typeof getTestApp>,
  mockEnv: any,
  email: string,
) {
  const registerRes = await app.request(
    jsonRequest("/auth/register", {
      method: "POST",
      body: JSON.stringify({ email, password: "password123", name: "Admin" }),
    }),
    {},
    mockEnv,
  );
  const cookie = getSessionCookie(registerRes)!;

  const meRes = await app.request(
    new Request("http://localhost/auth/me", { headers: { Cookie: `session=${cookie}` } }),
    {},
    mockEnv,
  );
  const userId = ((await meRes.json()) as any).user.id;

  await mockEnv.DB.exec(
    `INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES ('${userId}', 'role_admin')`,
  );

  return { cookie, userId };
}

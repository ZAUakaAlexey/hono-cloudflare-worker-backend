export interface SessionUser {
  id: string;
  email: string;
  name: string;
  isActive: boolean;
}

export interface Env {
  Bindings: {
    DB: D1Database;
    KV: KVNamespace;
    ENVIRONMENT: string;
  };
  Variables: {
    user: SessionUser | null;
    sessionToken: string | null;
  };
}

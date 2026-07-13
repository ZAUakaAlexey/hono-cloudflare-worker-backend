import { createApp } from "./app";
import { createDb } from "./db";
import {
  cleanupExpiredSessions,
  cleanupOldLoginAttempts,
  cleanupOldAuditLogs,
} from "./services/audit.service";

const app = createApp();

export default {
  fetch: app.fetch,

  async scheduled(event: ScheduledEvent, env: { DB: D1Database }) {
    const db = createDb(env.DB);

    const sessions = await cleanupExpiredSessions(db);
    const attempts = await cleanupOldLoginAttempts(db);
    const logs = await cleanupOldAuditLogs(db);

    console.log(`Cleanup: ${sessions} sessions, ${attempts} login attempts, ${logs} audit logs`);
  },
};

import { createMiddleware } from "hono/factory";
import type { Env } from "../types/env";

const SQL_PATTERNS = [
  /(\b)(union\s+select|select\s+.+\s+from|insert\s+into|update\s+.+\s+set|delete\s+from|drop\s+(table|database)|alter\s+table)(\b)/i,
  /('\s*(or|and)\s+'?\d*'?\s*[=<>])/i,
  /(;\s*(drop|delete|update|insert|alter|create)\s)/i,
];

const XSS_PATTERNS = [
  /<script[\s>]/i,
  /javascript\s*:/i,
  /on(load|error|click|mouseover|focus|blur|submit|change|input)\s*=/i,
  /\beval\s*\(/i,
  /\bdocument\.(cookie|write|location)/i,
  /\bwindow\.(location|open)\b/i,
];

const PATH_TRAVERSAL_PATTERNS = [
  /\.\.[/\\]/,
  /%2e%2e[/\\%]/i,
  /\.\.\\/,
];

const BLOCKED_USER_AGENTS = [
  /sqlmap/i,
  /nikto/i,
  /nessus/i,
  /openvas/i,
  /w3af/i,
  /havij/i,
];

function containsPattern(input: string, patterns: RegExp[]): boolean {
  return patterns.some((p) => p.test(input));
}

export const waf = createMiddleware<Env>(async (c, next) => {
  const url = new URL(c.req.url);
  const path = decodeURIComponent(url.pathname);
  const query = decodeURIComponent(url.search);
  const ua = c.req.header("user-agent") ?? "";

  if (containsPattern(ua, BLOCKED_USER_AGENTS)) {
    return c.json(
      { error: { code: "FORBIDDEN", message: "Request blocked" } },
      403,
    );
  }

  if (containsPattern(path, PATH_TRAVERSAL_PATTERNS)) {
    return c.json(
      { error: { code: "FORBIDDEN", message: "Request blocked" } },
      403,
    );
  }

  if (containsPattern(query, SQL_PATTERNS) || containsPattern(query, XSS_PATTERNS)) {
    return c.json(
      { error: { code: "FORBIDDEN", message: "Request blocked" } },
      403,
    );
  }

  if (c.req.method === "POST" || c.req.method === "PUT" || c.req.method === "PATCH") {
    try {
      const cloned = c.req.raw.clone();
      const text = await cloned.text();

      if (text && containsPattern(text, SQL_PATTERNS)) {
        return c.json(
          { error: { code: "FORBIDDEN", message: "Request blocked" } },
          403,
        );
      }
    } catch {}
  }

  return next();
});

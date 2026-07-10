import { defineConfig } from "vitest/config";
import { cloudflarePool } from "@cloudflare/vitest-pool-workers";

export default defineConfig({
  test: {
    pool: cloudflarePool({
      main: "./src/index.ts",
      wrangler: { configPath: "./wrangler.toml" },
    }),
  },
});

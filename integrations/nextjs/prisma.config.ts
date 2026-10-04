import { defineConfig, env } from "prisma/config";

// Prisma migrates as the owner (the migration role); the app connects as conf_app (ROWFENCE_APP_URL)
export default defineConfig({
  schema: "prisma/schema.prisma",
  migrations: { path: "prisma/migrations" },
  datasource: { url: env("ROWFENCE_OWNER_DSN") },
});

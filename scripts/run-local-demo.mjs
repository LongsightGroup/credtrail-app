import { spawnSync } from "node:child_process";

const result = spawnSync(
  "pnpm",
  ["exec", "playwright", "test", "--config", "playwright.config.mjs", "--project", "guided-demo"],
  {
    stdio: "inherit",
    env: {
      ...process.env,
      PWDEBUG: process.env.PWDEBUG ?? "0",
    },
  },
);

process.exitCode = result.status ?? 1;

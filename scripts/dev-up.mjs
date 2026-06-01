import { copyFileSync, existsSync } from "node:fs";
import { spawn, spawnSync } from "node:child_process";

import { loadLocalDevEnv } from "./local-dev-env.mjs";
import { printReadyBlock } from "./local-dev-ready-block.mjs";

const run = (command, args, options = {}) => {
  const result = spawnSync(command, args, {
    stdio: "inherit",
    env: process.env,
    ...options,
  });

  if (result.status !== 0) {
    const rendered = [command, ...args].join(" ");
    throw new Error(`${rendered} failed with exit code ${result.status ?? "unknown"}`);
  }
};

const copyIfMissing = (source, target) => {
  if (!existsSync(target)) {
    copyFileSync(source, target);
    console.log(`Created ${target} from ${source}`);
  }
};

const main = () => {
  copyIfMissing("wrangler.local.jsonc.example", "wrangler.local.jsonc");
  copyIfMissing(".dev.vars.local.example", ".dev.vars.local");
  loadLocalDevEnv();

  run("docker", ["compose", "-f", "docker-compose.dev.yml", "up", "-d", "postgres"]);
  run("pnpm", ["db:migrate:postgres"]);
  run("pnpm", ["dev:seed"]);

  printReadyBlock({ status: "starting" });

  const wrangler = spawn(
    "pnpm",
    [
      "exec",
      "wrangler",
      "dev",
      "--config",
      "wrangler.local.jsonc",
      "--env-file",
      ".dev.vars.local",
      "--port",
      "8787",
    ],
    {
      stdio: "inherit",
      env: process.env,
    },
  );

  const stop = () => {
    wrangler.kill("SIGINT");
  };

  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);

  wrangler.on("exit", (code) => {
    process.exitCode = code ?? 0;
  });
};

try {
  main();
} catch (error) {
  console.error(error);
  process.exitCode = 1;
}

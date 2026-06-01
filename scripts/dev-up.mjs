import { copyFileSync, existsSync } from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import net from "node:net";

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

const canConnect = (host, port) =>
  new Promise((resolve) => {
    const socket = net.createConnection({ host, port });
    const done = (result) => {
      socket.destroy();
      resolve(result);
    };

    socket.setTimeout(1000);
    socket.once("connect", () => done(true));
    socket.once("error", () => done(false));
    socket.once("timeout", () => done(false));
  });

const isComposePostgresRunning = () => {
  const result = spawnSync(
    "docker",
    ["compose", "-f", "docker-compose.dev.yml", "ps", "--status", "running", "-q", "postgres"],
    {
      encoding: "utf8",
      env: process.env,
    },
  );

  return result.status === 0 && result.stdout.trim().length > 0;
};

const localPostgresEndpoint = () => {
  const databaseUrl = new URL(
    process.env.DATABASE_URL?.trim() || "postgres://credtrail:credtrail@127.0.0.1:5432/credtrail",
  );

  return {
    host: databaseUrl.hostname || "127.0.0.1",
    port: Number(databaseUrl.port || "5432"),
  };
};

const preflightPostgresPort = async () => {
  const endpoint = localPostgresEndpoint();
  const portOccupied = await canConnect(endpoint.host, endpoint.port);

  if (!portOccupied || isComposePostgresRunning()) {
    return;
  }

  throw new Error(
    [
      `Postgres endpoint ${endpoint.host}:${String(endpoint.port)} is already accepting connections, but the CredTrail dev Postgres compose service is not running.`,
      "Stop the other Postgres process or keep docker-compose.dev.yml, wrangler.local.jsonc, and .dev.vars.local aligned on a different host port before running pnpm dev:up.",
    ].join("\n"),
  );
};

const main = async () => {
  copyIfMissing("wrangler.local.jsonc.example", "wrangler.local.jsonc");
  copyIfMissing(".dev.vars.local.example", ".dev.vars.local");
  loadLocalDevEnv();

  await preflightPostgresPort();
  run("docker", ["compose", "-f", "docker-compose.dev.yml", "up", "-d", "--wait", "postgres"]);
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

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

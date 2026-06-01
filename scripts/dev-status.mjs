import net from "node:net";

import { localDevDefaults, printReadyBlock } from "./local-dev-ready-block.mjs";

const canConnect = (host, port) =>
  new Promise((resolve) => {
    const socket = net.createConnection({ host, port });
    const done = (result) => {
      socket.destroy();
      resolve(result);
    };

    socket.setTimeout(1500);
    socket.once("connect", () => done(true));
    socket.once("error", () => done(false));
    socket.once("timeout", () => done(false));
  });

const main = async () => {
  const ready = localDevDefaults();
  const databaseUrl = new URL(
    process.env.DATABASE_URL?.trim() || "postgres://credtrail:credtrail@127.0.0.1:5432/credtrail",
  );
  const postgresHost = databaseUrl.hostname || "127.0.0.1";
  const postgresPort = Number(databaseUrl.port || "5432");
  const postgresReady = await canConnect(postgresHost, postgresPort);
  let wranglerReady = false;
  let wranglerStatus = null;

  try {
    const response = await fetch(new URL("/healthz/dependencies", ready.baseUrl), {
      redirect: "manual",
    });
    wranglerStatus = response.status;
    wranglerReady = response.ok;
  } catch {
    wranglerReady = false;
  }

  printReadyBlock({
    status: postgresReady && wranglerReady ? "ready" : "not_ready",
    checks: {
      postgres: {
        status: postgresReady ? "ok" : "unreachable",
        host: postgresHost,
        port: postgresPort,
      },
      wrangler: {
        status: wranglerReady ? "ok" : "unreachable",
        httpStatus: wranglerStatus,
        path: "/healthz/dependencies",
      },
    },
  });

  if (!postgresReady || !wranglerReady) {
    process.exitCode = 1;
  }
};

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

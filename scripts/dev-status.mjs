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
  const postgresReady = await canConnect("127.0.0.1", 5432);
  let wranglerReady = false;

  try {
    const response = await fetch(ready.baseUrl, { redirect: "manual" });
    wranglerReady = response.status > 0;
  } catch {
    wranglerReady = false;
  }

  printReadyBlock({
    status: postgresReady && wranglerReady ? "ready" : "not_ready",
    checks: {
      postgres: postgresReady ? "ok" : "unreachable",
      wrangler: wranglerReady ? "ok" : "unreachable",
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

import { spawnSync } from "node:child_process";

const result = spawnSync("docker", ["compose", "-f", "docker-compose.dev.yml", "down"], {
  stdio: "inherit",
});

process.exitCode = result.status ?? 1;

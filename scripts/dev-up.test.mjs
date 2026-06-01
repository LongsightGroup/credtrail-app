import { readFile } from "node:fs/promises";
import { test } from "node:test";
import assert from "node:assert/strict";

test("dev up waits for compose health before migrating", async () => {
  const source = await readFile(new URL("./dev-up.mjs", import.meta.url), "utf8");

  assert.match(source, /"up",\s*"-d",\s*"--wait",\s*"postgres"/);
  assert.match(source, /run\("pnpm",\s*\["db:migrate:postgres"\]\)/);
});

test("dev up preflights postgres port collisions", async () => {
  const source = await readFile(new URL("./dev-up.mjs", import.meta.url), "utf8");

  assert.match(source, /preflightPostgresPort/);
  assert.match(source, /isComposePostgresRunning/);
  assert.match(source, /already accepting connections/);
});

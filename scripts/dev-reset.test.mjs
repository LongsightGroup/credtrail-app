import { readFile } from "node:fs/promises";
import { test } from "node:test";
import assert from "node:assert/strict";

test("dev reset user cleanup uses the memberships table", async () => {
  const source = await readFile(new URL("./dev-reset.mjs", import.meta.url), "utf8");

  assert.match(source, /FROM memberships\b/);
  assert.doesNotMatch(source, /tenant_memberships/);
});

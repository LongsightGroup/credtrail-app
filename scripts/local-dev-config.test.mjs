import { readFile } from "node:fs/promises";
import { test } from "node:test";
import assert from "node:assert/strict";

test("local Wrangler example uses localhost issuer config", async () => {
  const source = await readFile(new URL("../wrangler.local.jsonc.example", import.meta.url), "utf8");

  assert.match(source, /"PLATFORM_DOMAIN":\s*"localhost"/);
  assert.match(source, /http:\/\/localhost:8787/);
  assert.match(source, /http:\/\/127\.0\.0\.1:8787/);
  assert.doesNotMatch(source, /credtrail\.example/);
});

test("local seed uses the same localhost issuer identity", async () => {
  const source = await readFile(new URL("./seed-local-dev.ts", import.meta.url), "utf8");

  assert.match(source, /issuerDomain:\s*"localhost"/);
  assert.match(source, /didWeb:\s*"did:web:localhost"/);
});

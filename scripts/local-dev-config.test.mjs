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

  assert.match(source, /issuerDomain:\s*primarySuffix\.length === 0 \? "localhost"/);
  assert.match(source, /primarySuffix\.length === 0 \? "did:web:localhost"/);
});

test("local seed creates the LMS connection before the seeded badge rule", async () => {
  const contractSource = await readFile(
    new URL("./local-dev-demo-contract.ts", import.meta.url),
    "utf8",
  );
  const seedSource = await readFile(new URL("./seed-local-dev.ts", import.meta.url), "utf8");
  const lmsConnectionIndex = seedSource.indexOf("await upsertTenantLmsConnection");
  const ruleIndex = seedSource.indexOf("await createBadgeIssuanceRule");

  assert.match(contractSource, /id:\s*localDevDemoRule\.lmsConnectionId/);
  assert.match(contractSource, /lmsConnectionId:\s*"local-demo-lms"/);
  assert.notEqual(lmsConnectionIndex, -1);
  assert.notEqual(ruleIndex, -1);
  assert.ok(lmsConnectionIndex < ruleIndex);
});

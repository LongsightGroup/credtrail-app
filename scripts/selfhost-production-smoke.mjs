import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { setTimeout } from "node:timers/promises";
import { chromium, request as playwrightRequest } from "@playwright/test";
import { prepareSmtpSmoke } from "./fixtures/selfhost-smtp-smoke.mjs";
import * as Ed25519Multikey from "@digitalbazaar/ed25519-multikey";

const imageIndex = process.argv.indexOf("--image");
const image = imageIndex < 0 ? undefined : process.argv[imageIndex + 1];
if (!image || image.startsWith("-"))
  throw new Error("Usage: node scripts/selfhost-production-smoke.mjs --image <built-image>");
const run = promisify(execFile);
const docker = async (...args) => {
  try {
    return (await run("docker", args, { maxBuffer: 4 * 1024 * 1024 })).stdout.trim();
  } catch (error) {
    throw new Error(`Docker ${args[0]} failed: ${error.stderr || "see local Docker diagnostics"}`);
  }
};
const prefix = `credtrail-smoke-${randomBytes(5).toString("hex")}`;
const network = `${prefix}-net`;
const containers = [];
const directory = await mkdtemp(join(tmpdir(), "credtrail-production-smoke-"));
let browser;
let http;
let smtp;
const availablePort = async () => {
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert(address && typeof address === "object");
  await new Promise((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
  return address.port;
};
const start = async (name, options, targetImage, command = []) => {
  await docker(
    "run",
    "-d",
    "--name",
    `${prefix}-${name}`,
    "--network",
    network,
    "--network-alias",
    name,
    ...options,
    targetImage,
    ...command,
  );
  containers.push(`${prefix}-${name}`);
};
const sql = async (statement) =>
  docker(
    "exec",
    `${prefix}-postgres`,
    "psql",
    "-U",
    "credtrail",
    "-d",
    "credtrail",
    "-v",
    "ON_ERROR_STOP=1",
    "-tAc",
    statement,
  );
const poll = async (action, label) => {
  for (let attempt = 0; attempt < 60; attempt++) {
    try {
      if (await action()) return;
    } catch {}
    await setTimeout(500);
  }
  throw new Error(`Timed out: ${label}`);
};
try {
  const port = await availablePort();
  const apiPort = await availablePort();
  const origin = `https://localhost:${port}`;
  const tenantId = "smoke_tenant";
  const badgeTemplateId = "smoke_template";
  const userId = "smoke_owner";
  const did = `did:web:localhost:${tenantId}`;
  const pair = generateKeyPairSync("ed25519");
  const privateJwk = pair.privateKey.export({ format: "jwk" });
  const publicJwk = pair.publicKey.export({ format: "jwk" });
  const key = await Ed25519Multikey.fromJwk({
    jwk: publicJwk,
    controller: did,
    id: `${did}#key-1`,
  });
  const publicKeyMultibase = (await key.export({ publicKey: true })).publicKeyMultibase;
  const processorToken = randomBytes(32).toString("hex");
  const apiKey = `ctak_${randomBytes(24).toString("hex")}`;
  const networkPart = randomBytes(1)[0];
  const subnet = `172.29.${networkPart}.0/24`;
  const proxyAddress = `172.29.${networkPart}.10`;
  await docker("network", "create", "--subnet", subnet, network);
  await start(
    "postgres",
    [
      "-e",
      "POSTGRES_USER=credtrail",
      "-e",
      "POSTGRES_PASSWORD=credtrail",
      "-e",
      "POSTGRES_DB=credtrail",
    ],
    "postgres:17-alpine",
  );
  await poll(
    async () =>
      (
        await docker(
          "exec",
          `${prefix}-postgres`,
          "pg_isready",
          "-h",
          "127.0.0.1",
          "-U",
          "credtrail",
        )
      ).includes("accepting connections"),
    "Postgres readiness",
  );
  const databaseUrl = "postgres://credtrail:credtrail@postgres:5432/credtrail";
  await docker(
    "run",
    "--rm",
    "--network",
    network,
    "-e",
    `DATABASE_URL=${databaseUrl}`,
    image,
    "node",
    "node_modules/@credtrail/db/scripts/migrate-postgres.mjs",
  );
  await docker("build", "-f", "Dockerfile.gofakes3", "-t", `${prefix}-s3-image`, ".");
  await start("s3", [], `${prefix}-s3-image`);
  await run("openssl", [
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-days",
    "1",
    "-keyout",
    join(directory, "key.pem"),
    "-out",
    join(directory, "cert.pem"),
    "-subj",
    "/CN=localhost",
    "-addext",
    "subjectAltName=DNS:localhost,DNS:smtp",
  ]);
  smtp = await prepareSmtpSmoke({ directory, network, image, docker, poll });
  const values = {
    APP_ENV: "production",
    PLATFORM_DOMAIN: "localhost",
    PUBLIC_APP_ORIGIN: origin,
    DATABASE_URL: databaseUrl,
    BETTER_AUTH_SECRET: randomBytes(32).toString("hex"),
    STORAGE_BACKEND: "s3",
    S3_ENDPOINT: "http://s3:9000",
    S3_BUCKET: "credtrail-badges",
    S3_REGION: "us-east-1",
    S3_FORCE_PATH_STYLE: "true",
    AWS_ACCESS_KEY_ID: "disposable",
    AWS_SECRET_ACCESS_KEY: "disposable",
    JOB_PROCESSOR_TOKEN: processorToken,
    TRUSTED_PROXY_CIDRS: `${proxyAddress}/32`,
    ...smtp.env,
    TENANT_SIGNING_REGISTRY_JSON: JSON.stringify({
      [did]: { tenantId, keyId: "key-1", publicJwk, privateJwk },
    }),
  };
  const envArgs = [
    ...smtp.mount,
    ...Object.entries(values).flatMap(([name, value]) => ["-e", `${name}=${value}`]),
  ];
  await docker(
    "run",
    "--rm",
    "--network",
    network,
    ...envArgs,
    image,
    "node",
    "--input-type=module",
    "-e",
    await readFile(new URL("./fixtures/selfhost-storage-contract.mjs", import.meta.url), "utf8"),
  );
  await start("app", ["-p", `127.0.0.1:${apiPort}:8787`, ...envArgs], image);
  await start(
    "proxy",
    [
      "--ip",
      proxyAddress,
      "-p",
      `127.0.0.1:${port}:443`,
      "-v",
      `${directory}:/certs:ro`,
      "-v",
      `${join(process.cwd(), "scripts/fixtures/selfhost-tls-proxy.conf")}:/etc/nginx/nginx.conf:ro`,
    ],
    "nginx:1.29-alpine",
  );
  http = await playwrightRequest.newContext({ ignoreHTTPSErrors: true });
  await poll(
    async () =>
      (await http.get(`http://127.0.0.1:${apiPort}/healthz/dependencies`)).status() === 200,
    "production Node database and storage health",
  );
  const wrongOrigin = await http.get(`http://127.0.0.1:${apiPort}/login`, { maxRedirects: 0 });
  assert.equal(wrongOrigin.status(), 308);
  const login = await http.get(`${origin}/login`);
  assert.equal(login.status(), 200);
  assert.equal((await http.get(`${origin}/ims/ob/v3p0/discovery`)).status(), 200);
  const html = await login.text();
  const assetUrls = [...html.matchAll(/(?:src|href)="([^"]*\/assets\/ui\/[^"]+)"/gu)].map(
    (match) => match[1],
  );
  assert(assetUrls.some((url) => url.endsWith(".js")));
  assert(assetUrls.some((url) => url.endsWith(".css")));
  const assets = [...assetUrls];
  for (const asset of assetUrls.filter((url) => url.endsWith(".css"))) {
    const stylesheet = await (await http.get(new URL(asset, origin).href)).text();
    for (const font of stylesheet.matchAll(/url\("([^"]+\.woff2)"\)/gu)) assets.push(font[1]);
  }
  assert(assets.some((url) => url.endsWith(".woff2")));
  const wrongAssetOrigin = await http.get(`http://127.0.0.1:${apiPort}${assetUrls[0]}`, {
    maxRedirects: 0,
  });
  assert.equal(wrongAssetOrigin.status(), 308);
  assert.equal(wrongAssetOrigin.headers().location, new URL(assetUrls[0], origin).href);
  const assetRequestId = "production-smoke-asset";
  const assertAssetPolicies = (response) => {
    const headers = response.headers();
    assert.equal(headers["x-request-id"], assetRequestId);
    assert.equal(headers["x-content-type-options"], "nosniff");
    assert.match(headers["strict-transport-security"], /max-age=/u);
    assert.equal(headers["referrer-policy"], "strict-origin-when-cross-origin");
    assert.match(headers["content-security-policy"], /default-src 'self'/u);
  };
  for (const asset of assets) {
    const response = await http.get(new URL(asset, origin).href, {
      headers: { "x-request-id": assetRequestId },
    });
    assert.equal(response.status(), 200);
    assertAssetPolicies(response);
    assert.match(response.headers()["cache-control"], /^public,/u);
    assert.match(
      response.headers()["content-type"],
      asset.endsWith(".css")
        ? /text\/css/u
        : asset.endsWith(".js")
          ? /javascript/u
          : /font\/woff2/u,
    );
    const head = await http.head(new URL(asset, origin).href, {
      headers: { "x-request-id": assetRequestId },
    });
    assert.equal(head.status(), 200);
    assertAssetPolicies(head);
    assert.equal((await head.body()).length, 0);
    assert.equal(head.headers()["content-type"], response.headers()["content-type"]);
    assert.equal(head.headers()["content-length"], response.headers()["content-length"]);
  }
  const missingAsset = await http.get(`${origin}/assets/ui/missing.css`, {
    headers: { "x-request-id": assetRequestId },
  });
  assert.equal(missingAsset.status(), 404);
  assertAssetPolicies(missingAsset);
  assert.equal(missingAsset.headers()["cache-control"], "no-store");
  const assetLogs = (await docker("logs", `${prefix}-app`)).split("\n").flatMap((line) => {
    try {
      const record = JSON.parse(line);
      return record.requestId === assetRequestId && record.message === "http_request"
        ? [record]
        : [];
    } catch {
      return [];
    }
  });
  assert(assetLogs.some((record) => record.method === "GET" && record.status === 200));
  assert(assetLogs.some((record) => record.method === "HEAD" && record.status === 200));
  assert(assetLogs.some((record) => record.status === 404));
  const namespace = await http.get(`${origin}/ns/trusted-credential/v1`);
  assert.equal(namespace.status(), 200);
  assert.match(namespace.headers()["content-type"], /application\/ld\+json/u);
  assert.match(namespace.headers()["cache-control"], /^public,/u);
  assert(namespace.headers().etag);
  assert.equal(
    (
      await http.get(`${origin}/ns/trusted-credential/v1`, {
        headers: { "if-none-match": namespace.headers().etag },
      })
    ).status(),
    304,
  );
  const extension = await namespace.json();
  assert.equal((await http.head(`${origin}/ns/trusted-credential/v1`)).status(), 200);
  browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  page.on("pageerror", (error) => console.error("Login browser error:", error.message));
  page.on("console", (message) => {
    if (message.type() === "error") console.error("Login browser console:", message.text());
  });
  await page.goto(`${origin}/login`);
  await page
    .locator('#magic-link-login-form input[name="email"]')
    .fill("missing-login@example.edu");
  const submitted = page.waitForResponse(
    (response) =>
      response.url().endsWith("/v1/auth/magic-link/request") &&
      response.request().method() === "POST",
  );
  await page.locator('#magic-link-login-form button[type="submit"]').click();
  assert.equal((await submitted).status(), 202);
  const validCsrf = await http.post(`${origin}/v1/auth/magic-link/request`, {
    headers: { cookie: "better-auth.session_token=unrecognized-test-cookie", origin },
    data: { email: "missing-cookie@example.edu" },
  });
  assert.equal(validCsrf.status(), 202);
  // Unknown accounts never send mail; SMTP delivery is checked for a seeded account below.
  for (let attempt = 1; attempt <= 3; attempt++) {
    const result = await http.post(`${origin}/v1/auth/magic-link/request`, {
      headers: {
        "x-forwarded-for": `203.0.113.${attempt}`,
        "cf-connecting-ip": `203.0.113.${attempt}`,
      },
      data: { email: `missing-${attempt}@example.edu` },
    });
    assert.equal(result.status(), attempt < 2 ? 202 : 428);
  }
  const csrf = await http.post(`${origin}/v1/auth/magic-link/request`, {
    headers: {
      cookie: "better-auth.session_token=unrecognized-test-cookie",
      origin: "https://attacker.example",
    },
    data: { email: "missing@example.edu" },
  });
  assert.equal(csrf.status(), 403);
  await sql(
    `INSERT INTO tenants (id,slug,display_name,plan_tier,issuer_domain,did_web) VALUES ('${tenantId}','smoke','Smoke institution','institution','localhost','${did}');
INSERT INTO users (id,email) VALUES ('${userId}','smoke-owner@example.edu');
INSERT INTO memberships (tenant_id,user_id,role) VALUES ('${tenantId}','${userId}','owner');
INSERT INTO tenant_org_units (id,tenant_id,unit_type,slug,display_name,parent_org_unit_id,created_by_user_id) VALUES ('${tenantId}:org:institution','${tenantId}','institution','institution','Smoke institution',NULL,'${userId}');
INSERT INTO badge_templates (id,tenant_id,slug,title,image_uri,created_by_user_id,owner_org_unit_id,governance_metadata_json) VALUES ('${badgeTemplateId}','${tenantId}','smoke','Smoke achievement','${origin}/badges/assets/${tenantId}/${badgeTemplateId}/asset_test','${userId}','${tenantId}:org:institution','{"stability":"institution_registry"}');
INSERT INTO tenant_api_keys (id,tenant_id,label,key_prefix,key_hash,scopes_json,created_by_user_id,created_at,updated_at) VALUES ('smoke_key','${tenantId}','Smoke API key','${apiKey.slice(0, 13)}','${createHash("sha256").update(apiKey).digest("hex")}','["queue.issue","queue.revoke","operations.read","templates.read","assertions.read"]','${userId}',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP);`,
  );
  const authHttp = await playwrightRequest.newContext({ ignoreHTTPSErrors: true });
  try {
    await smtp.verifyAuth({ http: authHttp, origin, sql, tenantId });
  } finally {
    await authHttp.dispose();
  }
  const imageObject = JSON.stringify({
    version: 1,
    mimeType: "image/png",
    byteSize: 8,
    base64Data: "iVBORw0KGgo=",
    uploadedAt: new Date().toISOString(),
    originalFilename: "smoke.png",
  });
  await docker(
    "run",
    "--rm",
    "--network",
    network,
    ...envArgs,
    image,
    "node",
    "--input-type=module",
    "-e",
    `import {S3Client,PutObjectCommand,HeadBucketCommand} from '@aws-sdk/client-s3'; const client=new S3Client({endpoint:process.env.S3_ENDPOINT,region:'us-east-1',forcePathStyle:true,credentials:{accessKeyId:'disposable',secretAccessKey:'disposable'}}); await client.send(new HeadBucketCommand({Bucket:'credtrail-badges'})); await client.send(new PutObjectCommand({Bucket:'credtrail-badges',Key:'tenants/${tenantId}/badge-template-images/${badgeTemplateId}/asset_test.json',Body:${JSON.stringify(imageObject)},IfNoneMatch:'*'})); client.destroy();`,
  );
  const payload = {
    tenantId,
    badgeTemplateId,
    recipientIdentity: "learner@example.edu",
    recipientIdentityType: "email",
    idempotencyKey: "smoke-issue",
  };
  const accepted = await http.post(`${origin}/v1/programmatic/issue`, {
    headers: { "x-api-key": apiKey },
    data: payload,
  });
  assert.equal(accepted.status(), 202);
  const envelope = await accepted.json();
  assert.equal(accepted.headers().location, envelope.statusUrl);
  assert.equal(new URL(envelope.statusUrl).origin, origin);
  const pending = await http.get(envelope.statusUrl, { headers: { "x-api-key": apiKey } });
  assert.equal(pending.status(), 200);
  assert.equal((await pending.json()).status, "pending");
  assert.equal(pending.headers()["cache-control"], "no-store");
  const templates = await http.get(`${origin}/v1/programmatic/templates?tenantId=${tenantId}`, { headers: { "x-api-key": apiKey } });
  assert.equal(templates.status(), 200);
  const templatePage = await templates.json();
  assert.equal(templatePage.templates[0].badgeTemplateId, badgeTemplateId);
  assert.equal(templatePage.templates[0].imageUrl, `${origin}/badges/assets/${tenantId}/${badgeTemplateId}/asset_test`);
  const apiDescription = await http.get(`${origin}/v1/programmatic/openapi.json`);
  assert.equal((await apiDescription.json()).servers[0].url, origin);
  await sql(`INSERT INTO job_queue_messages
(id,tenant_id,job_type,payload_json,idempotency_key,available_at,status,created_at,updated_at)
VALUES ('smoke-lifecycle','smoke_empty_tenant','process_badge_rule_lifecycle',
json_build_object('scheduledFor','2026-08-17T00:00:00.000Z')::text,'smoke-lifecycle',
CURRENT_TIMESTAMP::text,'pending',CURRENT_TIMESTAMP::text,CURRENT_TIMESTAMP::text)`);
  await start("worker", [...envArgs, "-e", "JOB_POLL_INTERVAL_MS=250"], image, [
    "node",
    "dist/node-runtime/node-worker-runtime.js",
  ]);
  try {
    await poll(
      async () =>
        (await sql("SELECT status FROM job_queue_messages WHERE idempotency_key='smoke-issue'")) ===
        "completed",
      "production queue issuance",
    );
  } catch {
    const failure = await sql(
      "SELECT row_to_json(j) FROM (SELECT status,last_error FROM job_queue_messages WHERE idempotency_key='smoke-issue') j",
    );
    throw new Error(`Production queue issuance failed: ${failure}`);
  }
  await poll(
    async () =>
      (await sql("SELECT status FROM job_queue_messages WHERE id='smoke-lifecycle'")) ===
      "completed",
    "production lifecycle queue job",
  );
  const row = JSON.parse(
    await sql(
      "SELECT row_to_json(a) FROM (SELECT id,public_id,vc_r2_key FROM assertions WHERE tenant_id='smoke_tenant') a",
    ),
  );
  assert.equal(row.id, envelope.assertionId);
  const completed = await http.get(envelope.statusUrl, { headers: { "x-api-key": apiKey } });
  const completion = await completed.json();
  assert.equal(completion.status, "completed");
  assert.equal(completion.result.badgeUrl, `${origin}/badges/${row.public_id}`);
  const assertions = await http.get(`${origin}/v1/programmatic/assertions?tenantId=${tenantId}&recipientIdentity=learner%40example.edu`, { headers: { "x-api-key": apiKey } });
  assert.equal((await assertions.json()).assertions[0].assertionId, row.id);
  const foreignRead = await http.get(`${origin}/v1/programmatic/templates?tenantId=smoke_empty_tenant`, { headers: { "x-api-key": apiKey } });
  assert.equal(foreignRead.status(), 403);
  assert(row.vc_r2_key.includes(encodeURIComponent(row.id)));
  const credentialResponse = await http.get(`${origin}/badges/${row.public_id}/jsonld`);
  assert.equal(credentialResponse.status(), 200);
  const credential = await credentialResponse.json();
  assert.equal(credential.id, `urn:credtrail:assertion:${encodeURIComponent(row.id)}`);
  assert(!credential["@context"].includes("https://credtrail.org/ns/trusted-credential/v1"));
  const verify = async () => {
    const response = await http.get(`${origin}/badges/${row.public_id}/verification`);
    assert.equal(response.status(), 200);
    return response.json();
  };
  const active = await verify();
  assert.equal(active.verification.status, "active");
  assert.equal(active.verification.proof.status, "valid");
  assert.equal(active.verification.checks.credentialStatus.status, "valid");
  // execFile has no stdin input option; spawn explicitly without exposing signed objects in logs.
  const { spawn } = await import("node:child_process");
  await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["scripts/verify-credential-interoperability.mjs"], {
      stdio: ["pipe", "pipe", "pipe"],
    });
    let errors = "";
    child.stderr.on("data", (chunk) => {
      errors += chunk;
    });
    child.once("error", reject);
    child.once("close", (code) =>
      code === 0
        ? resolve()
        : reject(new Error(`Independent smoke verification failed: ${errors}`)),
    );
    child.stdin.end(JSON.stringify({ credential, publicKeyMultibase, extension }));
  });
  const replay = await http.post(`${origin}/v1/programmatic/issue`, {
    headers: { "x-api-key": apiKey },
    data: payload,
  });
  assert.deepEqual(await replay.json(), envelope);
  assert.equal(await sql("SELECT COUNT(*) FROM assertions WHERE tenant_id='smoke_tenant'"), "1");
  const revoked = await http.post(`${origin}/v1/programmatic/revoke`, {
    headers: { "x-api-key": apiKey },
    data: {
      tenantId,
      assertionId: row.id,
      reason: "Smoke revocation",
      idempotencyKey: "smoke-revoke",
    },
  });
  assert.equal(revoked.status(), 202);
  await poll(
    async () =>
      (await sql("SELECT status FROM job_queue_messages WHERE idempotency_key='smoke-revoke'")) ===
      "completed",
    "queue revocation",
  );
  const revocationEnvelope = await revoked.json();
  const revocationStatus = await http.get(revocationEnvelope.statusUrl, { headers: { "x-api-key": apiKey } });
  assert.equal((await revocationStatus.json()).status, "completed");
  const revokedDetail = await http.get(`${origin}/v1/programmatic/assertions/${encodeURIComponent(row.id)}?tenantId=${tenantId}`, { headers: { "x-api-key": apiKey } });
  assert.equal((await revokedDetail.json()).state, "revoked");
  const inactive = await verify();
  assert.equal(inactive.verification.status, "revoked");
  assert.equal(inactive.verification.checks.credentialStatus.revoked, true);
  assert.equal((await docker("exec", `${prefix}-app`, "node", "--version")).split(".")[0], "v24");
  await smtp.verifyIssuance({ http, origin, sql, apiKey, payload, assertionId: row.id });
  console.log(
    "SMTP packaged no-send check/test, real sign-in, issuance acceptance/rejection audits, and production Node 24 API/worker, Postgres, S3 storage contracts, discovery, TLS POST/CSRF, packaged login assets/HTTP policies/request logs/browser script, forged-header IP limits, namespace, lifecycle queue job, issuance identity/replay, independent signature verification and active/revoked status checks passed.",
  );
} finally {
  await Promise.allSettled([browser?.close(), http?.dispose()]);
  for (const container of containers.reverse())
    await docker("rm", "-f", container).catch(() => undefined);
  await docker("network", "rm", network).catch(() => undefined);
  await docker("image", "rm", `${prefix}-s3-image`).catch(() => undefined);
  await smtp?.close();
  await rm(directory, { recursive: true, force: true });
}

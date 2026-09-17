import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { createPostgresDatabase } from "@credtrail/db/postgres";
import { learnerRecordImportQueuePayloadSchema } from "@credtrail/validation";
import { applyLearnerRecordImportQueuePayload } from "../../apps/api-worker/src/learner-record/learner-record-import-queue";
import { createLiveBadgeRuleApprovalFixture } from "./helpers/live-badge-rule-approval-fixture";
import { loadLocalDevEnv, requireEnv } from "../../scripts/local-dev-env.mjs";

test("import history supports CSV repair, honest progress, and saved learner records", async ({ page, baseURL }) => {
  const f = await createLiveBadgeRuleApprovalFixture();
  loadLocalDevEnv();
  const db = createPostgresDatabase({ databaseUrl: requireEnv("DATABASE_URL"), connectionMode: "single-use" });
  const path = `/tenants/${f.tenantId}/admin/operations/learner-record-imports`;
  const email = `import-${crypto.randomUUID()}@example.edu`;
  try {
    const login = new URL("/v1/dev/auth/login-as", baseURL);
    login.search = new URLSearchParams({ tenantId: f.tenantId, email: f.authorEmail, next: path }).toString();
    await page.goto(login.toString());
    await expect(page.locator('input[type="file"]')).toHaveCount(0);
    await page.getByRole("link", { name: "Import learner records", exact: true }).click();
    await page.getByLabel("CSV file").setInputFiles({ name: "learner-records.csv", mimeType: "text/csv", buffer: Buffer.from(`learnerEmail,title,recordType,issuedAt\n${email},Clinical Seminar,course,2026-09-17T00:00:00.000Z\ninvalid,Missing fields,course,invalid`) });
    await page.getByRole("button", { name: "Preview import", exact: true }).click();
    await expect(page.getByRole("button", { name: "Import 1 valid row", exact: true })).toBeVisible();
    await expect(page.getByText(/1 invalid row will be skipped/)).toBeVisible();
    await page.getByLabel("Show rows needing attention").check();
    await expect(page.locator('[data-import-preview-row][data-needs-attention="false"]:visible')).toHaveCount(0);
    const downloaded = page.waitForEvent("download");
    await page.getByRole("link", { name: "Download error report", exact: true }).click();
    const reportUrl = await page.getByRole("link", { name: "Download error report", exact: true }).getAttribute("href");
    expect(reportUrl).toBeTruthy();
    const anonymous = await page.request.get(reportUrl!, { headers: { Cookie: "" } });
    expect(anonymous.status()).toBe(401);
    const report = await downloaded;
    expect(await readFile((await report.path())!, "utf8")).toContain("invalid");
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.screenshot({ path: "/tmp/credtrail-import-desktop.png", fullPage: true, animations: "disabled" });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.evaluate(() => window.scrollTo(0, 0));
    await expect.poll(() => page.locator(".ct-admin-sidebar").evaluate(el => el.getBoundingClientRect().right)).toBeLessThanOrEqual(1);
    await page.screenshot({ path: "/tmp/credtrail-import-mobile.png", fullPage: true, animations: "disabled" });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.getByRole("button", { name: "Import 1 valid row", exact: true }).click();
    await expect(page.locator('#learner-import-progress')).toContainText("0 of 1 completed");
    await expect(page.getByRole("link", { name: "View imported learners" })).toHaveCount(0);
    const jobs = await db.prepare("SELECT id, payload_json AS payload FROM job_queue_messages WHERE tenant_id = ? AND job_type = 'import_learner_record_batch'").bind(f.tenantId).all<{ id: string; payload: string }>();
    expect(jobs.results).toHaveLength(1);
    for (const job of jobs.results) {
      await applyLearnerRecordImportQueuePayload(db, f.tenantId, learnerRecordImportQueuePayloadSchema.parse(JSON.parse(job.payload)));
      await db.prepare("UPDATE job_queue_messages SET status = 'completed', completed_at = ? WHERE tenant_id = ? AND id = ?").bind(new Date().toISOString(), f.tenantId, job.id).run();
    }
    await expect(page.locator('#learner-import-progress')).toContainText("1 of 1 completed", { timeout: 20000 });
    await page.getByRole("link", { name: "View imported learners", exact: true }).click();
    await expect(page.locator('#imported-learners')).toContainText(email);
    await page.getByRole("link", { name: "View learner record", exact: true }).click();
    await expect(page.getByText("Clinical Seminar", { exact: true })).toBeVisible();
    await page.goto(`${path}?upload=1`);
    await page.getByLabel("CSV file").setInputFiles({ name: "invalid.csv", mimeType: "text/csv", buffer: Buffer.from("learnerEmail,title,recordType,issuedAt\ninvalid,Invalid record,course,invalid") });
    await page.getByRole("button", { name: "Preview import", exact: true }).click();
    await expect(page.getByText("No valid rows are ready to import. Correct the CSV and preview it again.")).toBeVisible();
    const invalidUrl = await page.getByRole("link", { name: "Download error report", exact: true }).getAttribute("href");
    expect((await page.request.get(invalidUrl!)).status()).toBe(200);
    await db.prepare("UPDATE learner_record_import_previews SET expires_at = '2020-01-01T00:00:00.000Z' WHERE tenant_id = ?").bind(f.tenantId).run();
    expect((await page.request.get(invalidUrl!)).status()).toBe(404);
  } finally { await f.dispose(); }
});

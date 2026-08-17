import type { ImmutableCredentialStore, JsonObject } from "@credtrail/core-domain";
import { listBadgeTemplates } from "@credtrail/db";
import { parseQueueJob } from "@credtrail/validation";
import { expect, it } from "vitest";
import {
  cleanupTestResources,
  createTestTenantFixture,
  describeDbIntegration,
} from "../../../../packages/db/src/postgres-test-support";
import type { DirectIssueBadgeOptions, DirectIssueBadgeResult } from "../badges/direct-issue";
import type { DirectIssueBadgeRequest } from "../badges/recipient-identifiers";
import type { PublicJsonNetwork } from "../http/public-json-network";
import { processMigrationBatchQueueJob } from "./migration-batch-queue-job";

const PNG_SIGNATURE = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

const imageStore = (): { store: ImmutableCredentialStore; writtenKeys: string[] } => {
  const writtenKeys: string[] = [];

  return {
    writtenKeys,
    store: {
      head: () => Promise.resolve(null),
      get: () => Promise.resolve(null),
      put: (key, value) => {
        writtenKeys.push(key);
        return Promise.resolve({
          key,
          etag: "test-etag",
          version: "test-version",
          size: value.length,
          uploaded: new Date("2026-08-17T00:00:00.000Z"),
        });
      },
      delete: () => Promise.resolve(),
    },
  };
};

const imageNetwork = (): PublicJsonNetwork => ({
  resolveHostname: () => Promise.resolve([{ address: "93.184.216.34", family: 4 }]),
  request: () =>
    Promise.resolve({
      status: "received",
      statusCode: 200,
      location: null,
      bodyBytes: PNG_SIGNATURE,
    }),
});

describeDbIntegration("migration batch queue processing with Postgres", () => {
  it("upserts template artwork and issues idempotently on retry", async () => {
    const fixture = await createTestTenantFixture();
    const { store, writtenKeys } = imageStore();
    const job = parseQueueJob({
      jobType: "import_migration_batch",
      tenantId: fixture.tenantId,
      payload: {
        source: "file_upload",
        batchId: "batch_123",
        rowNumber: 1,
        fileName: "badges.json",
        format: "json",
        requestedAt: "2026-08-17T00:00:00.000Z",
        conversion: {
          createBadgeTemplateRequest: {
            slug: "migration-foundations",
            title: "Migration Foundations",
            description: "Imported badge",
            imageUri: "https://issuer.example.edu/badges/migration.png",
          },
          manualIssueRequest: {
            recipientIdentity: "learner@example.edu",
            recipientIdentityType: "email",
          },
          issueOptions: {
            recipientDisplayName: "Learner Example",
          },
          sourceMetadata: {
            issuedOn: "2026-08-16T00:00:00.000Z",
            evidenceUrls: [],
            recipientHashed: false,
          },
          warnings: [],
        },
      },
      idempotencyKey: "migration-batch:batch_123:1",
    });

    if (job.jobType !== "import_migration_batch") {
      throw new Error("Expected migration queue job");
    }

    const issueRequests: Array<{
      idempotencyKey: string | undefined;
      imageUri: string | null;
      options: DirectIssueBadgeOptions | undefined;
    }> = [];
    const issueBadgeForTenant = (
      _context: Record<string, never>,
      tenantId: string,
      request: DirectIssueBadgeRequest,
      _issuedByUserId?: string,
      options?: DirectIssueBadgeOptions,
    ): Promise<DirectIssueBadgeResult> => {
      const snapshot =
        request.achievementSource.kind === "template_snapshot"
          ? request.achievementSource.snapshot
          : null;

      issueRequests.push({
        idempotencyKey: request.idempotencyKey,
        imageUri: snapshot?.imageUri ?? null,
        options,
      });

      return Promise.resolve({
        status: issueRequests.length === 1 ? "issued" : "already_issued",
        tenantId,
        assertionId: "assertion_123",
        idempotencyKey: request.idempotencyKey ?? "missing",
        vcR2Key: "assertions/assertion_123.jsonld",
        credential: {} satisfies JsonObject,
      });
    };

    try {
      const process = () =>
        processMigrationBatchQueueJob({
          context: {},
          db: fixture.db,
          tenantId: fixture.tenantId,
          payload: job.payload,
          idempotencyKey: job.idempotencyKey,
          store,
          publicAppOrigin: "https://credtrail.test",
          publicJsonNetwork: imageNetwork(),
          issueBadgeForTenant,
        });

      await expect(process()).resolves.toMatchObject({ status: "issued" });
      await expect(process()).resolves.toMatchObject({ status: "already_issued" });

      const templates = await listBadgeTemplates(fixture.db, {
        tenantId: fixture.tenantId,
        includeArchived: true,
      });

      expect(templates).toHaveLength(1);
      expect(templates[0]?.slug).toBe("migration-foundations");
      expect(templates[0]?.imageUri).toContain("/badges/assets/");
      expect(new Set(writtenKeys).size).toBe(1);
      expect(issueRequests).toEqual([
        {
          idempotencyKey: "migration-batch:batch_123:1",
          imageUri: templates[0]?.imageUri ?? null,
          options: {
            issuedAt: "2026-08-16T00:00:00.000Z",
            recipientDisplayName: "Learner Example",
            sendEmailNotification: false,
          },
        },
        {
          idempotencyKey: "migration-batch:batch_123:1",
          imageUri: templates[0]?.imageUri ?? null,
          options: {
            issuedAt: "2026-08-16T00:00:00.000Z",
            recipientDisplayName: "Learner Example",
            sendEmailNotification: false,
          },
        },
      ]);
      await expect(
        fixture.db
          .prepare(
            "DELETE FROM badge_template_ownership_events WHERE tenant_id = ? AND badge_template_id = ?",
          )
          .bind(fixture.tenantId, templates[0]?.id)
          .run(),
      ).rejects.toThrow("badge_template_ownership_events is immutable");
    } finally {
      await cleanupTestResources(fixture.db, { tenantIds: [fixture.tenantId] });
    }
  });
});

import type { BadgeIssuanceRuleVersionRecord, SqlDatabase } from "@credtrail/db";
import { describe, expect, it } from "vitest";
import { parseBadgeIssuanceRuleDefinition } from "@credtrail/validation";
import { buildBadgeRuleVersionRecord } from "../test-support/badge-rule-version";
import {
  createBadgeRuleVersionReferenceLabelService,
  type BadgeRuleVersionReferenceLabelServiceDependencies,
} from "./badge-rule-version-reference-label-service";

const courseId = "course_101";
const courseTitle = "Advanced TypeScript";

const version = (): BadgeIssuanceRuleVersionRecord =>
  buildBadgeRuleVersionRecord({
    id: "brv_detail",
    ruleId: "brl_detail",
    status: "active",
    ruleJson:
      '{"conditions":{"type":"assignment_submission","courseId":"course_101","assignmentId":"assignment_7","requireSubmitted":true,"minScore":80}}',
    snapshot: {
      lmsConnectionId: "lms_snapshot",
    },
  });

const dependencies = (
  overrides: Partial<BadgeRuleVersionReferenceLabelServiceDependencies> = {},
): BadgeRuleVersionReferenceLabelServiceDependencies => ({
  findVersion: () => Promise.resolve(version()),
  listApprovalSteps: () => Promise.resolve([]),
  actorCanView: () => Promise.resolve(true),
  resolveDefinitionValueLists: (_db, _tenantId, definition) => Promise.resolve(definition),
  lmsReferenceLabels: {
    resolve: () =>
      Promise.resolve({
        status: "resolved",
        labels: {
          courses: [{ courseId, title: courseTitle }],
          assignments: [],
        },
      }),
  },
  ...overrides,
});

const input = {
  db: {} as SqlDatabase,
  tenantId: "tenant_123",
  ruleId: "brl_detail",
  versionId: "brv_detail",
  actorUserId: "usr_reviewer",
  actorRole: "approver" as const,
};

describe("badge rule version reference label service", () => {
  it("passes the snapshot connection and actor to the LMS label context", async () => {
    const connectionIds: string[] = [];
    const actorUserIds: string[] = [];
    const service = createBadgeRuleVersionReferenceLabelService(
      dependencies({
        lmsReferenceLabels: {
          resolve: (labelInput) => {
            connectionIds.push(labelInput.lmsConnectionId ?? "none");
            actorUserIds.push(labelInput.actorUserId);
            return Promise.resolve({
              status: "resolved",
              labels: {
                courses: [{ courseId, title: courseTitle }],
                assignments: [],
              },
            });
          },
        },
      }),
    );

    const result = await service(input);

    expect(result).toEqual({
      status: "resolved",
      labels: {
        courses: [{ courseId, title: courseTitle }],
        assignments: [],
      },
    });
    expect(connectionIds).toEqual(["lms_snapshot"]);
    expect(actorUserIds).toEqual(["usr_reviewer"]);
  });

  it("expands course lists before LMS label resolution", async () => {
    const expandedDefinition = parseBadgeIssuanceRuleDefinition({
      conditions: {
        type: "grade_threshold",
        courseId,
        minScore: 80,
      },
    });
    const labelDefinitions: (typeof expandedDefinition)[] = [];
    const service = createBadgeRuleVersionReferenceLabelService(
      dependencies({
        findVersion: () =>
          Promise.resolve({
            ...version(),
            ruleJson: JSON.stringify({
              conditions: {
                type: "grade_threshold",
                courseListId: "brvl_courses",
                minScore: 80,
              },
            }),
          }),
        resolveDefinitionValueLists: () => Promise.resolve(expandedDefinition),
        lmsReferenceLabels: {
          resolve: (labelInput) => {
            labelDefinitions.push(labelInput.definition);
            return Promise.resolve({
              status: "resolved",
              labels: {
                courses: [{ courseId, title: courseTitle }],
                assignments: [],
              },
            });
          },
        },
      }),
    );

    const result = await service(input);

    expect(result.status).toBe("resolved");
    expect(labelDefinitions).toEqual([expandedDefinition]);
  });

  it("propagates actionable LMS lookup failures", async () => {
    const service = createBadgeRuleVersionReferenceLabelService(
      dependencies({
        lmsReferenceLabels: {
          resolve: () =>
            Promise.resolve({
              status: "bad_gateway",
              error:
                "Sakai blocked CredTrail from reading this course gradebook (403). Confirm that the saved Sakai account can view the course and gradebook, then try again.",
            }),
        },
      }),
    );

    expect(await service(input)).toEqual({
      status: "bad_gateway",
      error:
        "Sakai blocked CredTrail from reading this course gradebook (403). Confirm that the saved Sakai account can view the course and gradebook, then try again.",
    });
  });

  it("stops before LMS access when the actor cannot view the version", async () => {
    let lmsResolutionCount = 0;
    const service = createBadgeRuleVersionReferenceLabelService(
      dependencies({
        actorCanView: () => Promise.resolve(false),
        lmsReferenceLabels: {
          resolve: () => {
            lmsResolutionCount += 1;
            return Promise.resolve({
              status: "resolved",
              labels: { courses: [], assignments: [] },
            });
          },
        },
      }),
    );

    expect(await service(input)).toEqual({
      status: "forbidden",
      error: "Approval step not assigned to this reviewer",
    });
    expect(lmsResolutionCount).toBe(0);
  });
});

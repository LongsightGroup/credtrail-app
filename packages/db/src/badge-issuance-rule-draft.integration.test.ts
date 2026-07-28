import { expect, it } from "vitest";

import * as dbModule from "./index";
import { createFixtureRule } from "./badge-issuance-rule-test-fixtures";
import {
  cleanupTestResources,
  createBadgeRuleIntegrationFixture,
  createDepartmentCourseOrgUnitHierarchy,
  describeDbIntegration,
  selectCount,
} from "./postgres-test-support";

describeDbIntegration("badge issuance rule draft DB helpers with Postgres", () => {
  it("persists incomplete builder drafts without creating rule versions", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const draft = await dbModule.saveBadgeIssuanceRuleBuilderDraft(fixture.db, {
        id: "brd_first",
        tenantId: fixture.tenantId,
        userId: fixture.userId,
        target: { kind: "unfinished" },
        currentStep: "metadata",
        draftJson: JSON.stringify({
          badgeTemplateId: fixture.badgeTemplateId,
          definitionJson: "",
        }),
      });
      const loaded = await dbModule.findBadgeIssuanceRuleBuilderDraftById(fixture.db, {
        tenantId: fixture.tenantId,
        userId: fixture.userId,
        draftId: "brd_first",
      });
      const versionCount = await selectCount(
        fixture.db,
        "SELECT COUNT(*) AS totalCount FROM badge_issuance_rule_versions WHERE tenant_id = ?",
        [fixture.tenantId],
      );

      expect(draft.status).toBe("saved");
      expect(draft.status === "saved" ? draft.draft.currentStep : null).toBe("metadata");
      expect(loaded?.draftJson).toContain(fixture.badgeTemplateId);
      expect(versionCount).toBe(0);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("deletes saved builder drafts for a user and rule scope", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      await dbModule.saveBadgeIssuanceRuleBuilderDraft(fixture.db, {
        id: "brd_delete",
        tenantId: fixture.tenantId,
        userId: fixture.userId,
        target: { kind: "unfinished" },
        currentStep: "conditions",
        draftJson: JSON.stringify({ definitionJson: "{}" }),
      });

      const deleted = await dbModule.deleteBadgeIssuanceRuleBuilderDraftById(fixture.db, {
        tenantId: fixture.tenantId,
        userId: fixture.userId,
        draftId: "brd_delete",
      });
      const loaded = await dbModule.findBadgeIssuanceRuleBuilderDraftById(fixture.db, {
        tenantId: fixture.tenantId,
        userId: fixture.userId,
        draftId: "brd_delete",
      });

      expect(deleted?.id).toBe("brd_delete");
      expect(loaded).toBeNull();
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("keeps multiple unfinished drafts distinct and lists the user's drafts", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      await dbModule.saveBadgeIssuanceRuleBuilderDraft(fixture.db, {
        id: "brd_alpha",
        tenantId: fixture.tenantId,
        userId: fixture.userId,
        target: { kind: "unfinished" },
        currentStep: "metadata",
        draftJson: JSON.stringify({ name: "Alpha" }),
      });
      await dbModule.saveBadgeIssuanceRuleBuilderDraft(fixture.db, {
        id: "brd_beta",
        tenantId: fixture.tenantId,
        userId: fixture.userId,
        target: { kind: "unfinished" },
        currentStep: "conditions",
        draftJson: JSON.stringify({ name: "Beta" }),
      });

      const drafts = await dbModule.listBadgeIssuanceRuleBuilderDraftsForUser(fixture.db, {
        tenantId: fixture.tenantId,
        userId: fixture.userId,
      });

      expect(drafts.map((draft) => draft.id).sort()).toEqual(["brd_alpha", "brd_beta"]);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("rejects a formal builder target whose version belongs to another rule", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const firstRule = await createFixtureRule(fixture);
      const secondRule = await dbModule.createBadgeIssuanceRule(fixture.db, {
        tenantId: fixture.tenantId,
        name: "Second rule",
        badgeTemplateId: fixture.badgeTemplateId,
        lmsProviderKind: "canvas",
        lmsConnectionId: fixture.lmsConnectionId,
        ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_202","minScore":70}}',
        createdByUserId: fixture.userId,
      });

      await expect(
        dbModule.saveBadgeIssuanceRuleBuilderDraft(fixture.db, {
          id: "brd_mismatched_target",
          tenantId: fixture.tenantId,
          userId: fixture.userId,
          target: {
            kind: "formal_rule",
            ruleId: firstRule.rule.id,
            versionId: secondRule.version.id,
          },
          currentStep: "conditions",
          draftJson: JSON.stringify({ name: "Invalid target" }),
        }),
      ).rejects.toThrow(/./);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("atomically promotes the selected unfinished draft into a formal rule", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      await dbModule.saveBadgeIssuanceRuleBuilderDraft(fixture.db, {
        id: "brd_promote",
        tenantId: fixture.tenantId,
        userId: fixture.userId,
        target: { kind: "unfinished" },
        currentStep: "test",
        draftJson: JSON.stringify({ name: "Promote me" }),
      });

      const created = await dbModule.createBadgeIssuanceRuleFromBuilderDraft(fixture.db, {
        tenantId: fixture.tenantId,
        builderDraftId: "brd_promote",
        builderUserId: fixture.userId,
        name: "Promoted rule",
        badgeTemplateId: fixture.badgeTemplateId,
        lmsProviderKind: "canvas",
        lmsConnectionId: fixture.lmsConnectionId,
        ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":80}}',
        createdByUserId: fixture.userId,
      });
      const replayed = await dbModule.createBadgeIssuanceRuleFromBuilderDraft(fixture.db, {
        tenantId: fixture.tenantId,
        builderDraftId: "brd_promote",
        builderUserId: fixture.userId,
        name: "A retry must not create this second name",
        badgeTemplateId: fixture.badgeTemplateId,
        lmsProviderKind: "canvas",
        lmsConnectionId: fixture.lmsConnectionId,
        ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":90}}',
        createdByUserId: fixture.userId,
      });
      const lateSave = await dbModule.saveBadgeIssuanceRuleBuilderDraft(fixture.db, {
        id: "brd_promote",
        tenantId: fixture.tenantId,
        userId: fixture.userId,
        target: { kind: "unfinished" },
        currentStep: "test",
        draftJson: JSON.stringify({ name: "Must not reappear" }),
      });
      const remainingDraft = await dbModule.findBadgeIssuanceRuleBuilderDraftById(fixture.db, {
        tenantId: fixture.tenantId,
        userId: fixture.userId,
        draftId: "brd_promote",
      });
      const ruleCount = await selectCount(
        fixture.db,
        "SELECT COUNT(*) AS totalCount FROM badge_issuance_rules WHERE tenant_id = ?",
        [fixture.tenantId],
      );

      expect(created.status).toBe("created");
      expect(created.status === "unavailable" ? null : created.draft.rule.name).toBe(
        "Promoted rule",
      );
      expect(created.status === "unavailable" ? null : created.draft.version.status).toBe("draft");
      expect(replayed.status).toBe("replayed");
      expect(replayed.status === "unavailable" ? null : replayed.draft.rule.name).toBe(
        "Promoted rule",
      );
      expect(lateSave.status).toBe("unavailable");
      expect(ruleCount).toBe(1);
      expect(remainingDraft).toBeNull();
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("creates and submits one builder version in the same transaction", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      await dbModule.saveBadgeIssuanceRuleBuilderDraft(fixture.db, {
        id: "brd_submit",
        tenantId: fixture.tenantId,
        userId: fixture.userId,
        target: { kind: "unfinished" },
        currentStep: "review",
        draftJson: JSON.stringify({ name: "Submit me" }),
      });

      const result = await dbModule.createBadgeIssuanceRuleWithAction(fixture.db, {
        tenantId: fixture.tenantId,
        builderDraftId: "brd_submit",
        name: "Submitted rule",
        badgeTemplateId: fixture.badgeTemplateId,
        lmsProviderKind: "canvas",
        lmsConnectionId: fixture.lmsConnectionId,
        ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":80}}',
        action: "submit_for_approval",
        actorUserId: fixture.userId,
        actorRole: "admin",
      });
      const replayed = await dbModule.createBadgeIssuanceRuleWithAction(fixture.db, {
        tenantId: fixture.tenantId,
        builderDraftId: "brd_submit",
        name: "A retry must not replace the submitted rule",
        badgeTemplateId: fixture.badgeTemplateId,
        lmsProviderKind: "canvas",
        lmsConnectionId: fixture.lmsConnectionId,
        ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":90}}',
        action: "submit_for_approval",
        actorUserId: fixture.userId,
        actorRole: "admin",
      });
      const versionCount = await selectCount(
        fixture.db,
        "SELECT COUNT(*) AS totalCount FROM badge_issuance_rule_versions WHERE tenant_id = ?",
        [fixture.tenantId],
      );
      const approvalStepCount = await selectCount(
        fixture.db,
        "SELECT COUNT(*) AS totalCount FROM badge_issuance_rule_approval_steps WHERE tenant_id = ?",
        [fixture.tenantId],
      );
      const remainingDraft = await dbModule.findBadgeIssuanceRuleBuilderDraftById(fixture.db, {
        tenantId: fixture.tenantId,
        userId: fixture.userId,
        draftId: "brd_submit",
      });

      expect(result.status).toBe("completed");
      expect(result.status === "completed" ? result.outcome : null).toBe("pending_approval");
      expect(result.status === "completed" ? result.version.status : null).toBe("pending_approval");
      expect(result.status === "completed" ? result.pendingStepNumber : null).toBe(1);
      expect(replayed.status).toBe("completed");
      expect(replayed.status === "completed" ? replayed.writeStatus : null).toBe("replayed");
      expect(replayed.status === "completed" ? replayed.pendingStepNumber : null).toBe(1);
      expect(versionCount).toBe(1);
      expect(approvalStepCount).toBe(1);
      expect(remainingDraft).toBeNull();
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("never advances a replayed builder identity through a new lifecycle transition", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      await dbModule.saveBadgeIssuanceRuleBuilderDraft(fixture.db, {
        id: "brd_replay_without_transition",
        tenantId: fixture.tenantId,
        userId: fixture.userId,
        target: { kind: "unfinished" },
        currentStep: "review",
        draftJson: JSON.stringify({ name: "Replay without transition" }),
      });
      const created = await dbModule.createBadgeIssuanceRuleWithAction(fixture.db, {
        tenantId: fixture.tenantId,
        builderDraftId: "brd_replay_without_transition",
        name: "Saved rule",
        badgeTemplateId: fixture.badgeTemplateId,
        lmsProviderKind: "canvas",
        lmsConnectionId: fixture.lmsConnectionId,
        ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":80}}',
        action: "save_draft",
        actorUserId: fixture.userId,
        actorRole: "admin",
      });

      if (created.status !== "completed") {
        throw new Error(`Expected completed authoring, received ${created.status}`);
      }

      const replayedDraft = await dbModule.createBadgeIssuanceRuleWithAction(fixture.db, {
        tenantId: fixture.tenantId,
        builderDraftId: "brd_replay_without_transition",
        name: "A retry must not submit this draft",
        badgeTemplateId: fixture.badgeTemplateId,
        lmsProviderKind: "canvas",
        lmsConnectionId: fixture.lmsConnectionId,
        ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":90}}',
        action: "submit_for_approval",
        actorUserId: fixture.userId,
        actorRole: "admin",
      });
      await fixture.db
        .prepare("UPDATE badge_issuance_rule_versions SET status = 'rejected' WHERE id = ?")
        .bind(created.version.id)
        .run();
      const replayedRejected = await dbModule.createBadgeIssuanceRuleWithAction(fixture.db, {
        tenantId: fixture.tenantId,
        builderDraftId: "brd_replay_without_transition",
        name: "A retry must not resubmit this rejection",
        badgeTemplateId: fixture.badgeTemplateId,
        lmsProviderKind: "canvas",
        lmsConnectionId: fixture.lmsConnectionId,
        ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":95}}',
        action: "submit_for_approval",
        actorUserId: fixture.userId,
        actorRole: "admin",
      });
      const persistedVersion = await dbModule.findBadgeIssuanceRuleVersionById(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        versionId: created.version.id,
      });
      const approvalStepCount = await selectCount(
        fixture.db,
        "SELECT COUNT(*) AS totalCount FROM badge_issuance_rule_approval_steps WHERE tenant_id = ? AND version_id = ?",
        [fixture.tenantId, created.version.id],
      );

      expect(replayedDraft.status).toBe("completed");
      expect(replayedDraft.status === "completed" ? replayedDraft.outcome : null).toBe(
        "draft_saved",
      );
      expect(replayedDraft.status === "completed" ? replayedDraft.version.status : null).toBe(
        "draft",
      );
      expect(replayedRejected.status).toBe("replay_conflict");
      expect(persistedVersion?.status).toBe("rejected");
      expect(approvalStepCount).toBe(0);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("rolls back the formal rule when its approval policy rejects submission", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      await dbModule.upsertBadgeRuleApprovalPolicy(fixture.db, {
        tenantId: fixture.tenantId,
        approvalRequirement: "never",
        allowSelfCertification: false,
        approvalSteps: [],
        createdByUserId: fixture.userId,
      });
      await dbModule.saveBadgeIssuanceRuleBuilderDraft(fixture.db, {
        id: "brd_rejected_submission",
        tenantId: fixture.tenantId,
        userId: fixture.userId,
        target: { kind: "unfinished" },
        currentStep: "review",
        draftJson: JSON.stringify({ name: "Keep unfinished" }),
      });

      const result = await dbModule.createBadgeIssuanceRuleWithAction(fixture.db, {
        tenantId: fixture.tenantId,
        builderDraftId: "brd_rejected_submission",
        name: "Must roll back",
        badgeTemplateId: fixture.badgeTemplateId,
        lmsProviderKind: "canvas",
        lmsConnectionId: fixture.lmsConnectionId,
        ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":80}}',
        action: "submit_for_approval",
        actorUserId: fixture.userId,
        actorRole: "admin",
      });
      const ruleCount = await selectCount(
        fixture.db,
        "SELECT COUNT(*) AS totalCount FROM badge_issuance_rules WHERE tenant_id = ?",
        [fixture.tenantId],
      );
      const versionCount = await selectCount(
        fixture.db,
        "SELECT COUNT(*) AS totalCount FROM badge_issuance_rule_versions WHERE tenant_id = ?",
        [fixture.tenantId],
      );
      const remainingDraft = await dbModule.findBadgeIssuanceRuleBuilderDraftById(fixture.db, {
        tenantId: fixture.tenantId,
        userId: fixture.userId,
        draftId: "brd_rejected_submission",
      });

      expect(result.status).toBe("self_certification_required");
      expect(ruleCount).toBe(0);
      expect(versionCount).toBe(0);
      expect(remainingDraft?.currentStep).toBe("review");
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("reports immediate policy approval as an approved authoring outcome", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      await dbModule.upsertBadgeRuleApprovalPolicy(fixture.db, {
        tenantId: fixture.tenantId,
        approvalRequirement: "never",
        allowSelfCertification: true,
        approvalSteps: [],
        createdByUserId: fixture.userId,
      });

      const result = await dbModule.createBadgeIssuanceRuleWithAction(fixture.db, {
        tenantId: fixture.tenantId,
        name: "Automatically approved rule",
        badgeTemplateId: fixture.badgeTemplateId,
        lmsProviderKind: "canvas",
        lmsConnectionId: fixture.lmsConnectionId,
        ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":80}}',
        action: "submit_for_approval",
        actorUserId: fixture.userId,
        actorRole: "admin",
      });

      expect(result.status).toBe("completed");
      expect(result.status === "completed" ? result.outcome : null).toBe("approved");
      expect(result.status === "completed" ? result.version.approvedByUserId : null).toBe(
        fixture.userId,
      );
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("creates and lists rules by explicit org-unit descendant scope", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const { department, course } = await createDepartmentCourseOrgUnitHierarchy(fixture.db, {
        tenantId: fixture.tenantId,
        userId: fixture.userId,
      });
      const created = await dbModule.createBadgeIssuanceRule(fixture.db, {
        tenantId: fixture.tenantId,
        name: "CS101 Rule",
        badgeTemplateId: fixture.badgeTemplateId,
        orgUnitId: course.id,
        lmsProviderKind: "canvas",
        lmsConnectionId: fixture.lmsConnectionId,
        ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":80}}',
        createdByUserId: fixture.userId,
      });

      const scopedRules = await dbModule.listBadgeIssuanceRules(fixture.db, {
        tenantId: fixture.tenantId,
        scope: {
          type: "descendants",
          rootOrgUnitIds: [department.id],
        },
      });
      const siblingRules = await dbModule.listBadgeIssuanceRules(fixture.db, {
        tenantId: fixture.tenantId,
        scope: {
          type: "org_unit",
          orgUnitId: department.id,
        },
      });
      const updated = await dbModule.updateBadgeIssuanceRuleDraft(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        name: "CS101 Rule Revised",
        badgeTemplateId: fixture.badgeTemplateId,
        lmsProviderKind: "canvas",
        lmsConnectionId: fixture.lmsConnectionId,
        ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":85}}',
        createdByUserId: fixture.userId,
      });

      expect(created.rule.orgUnitId).toBe(course.id);
      expect(created.rule.ownerOrgUnitId).toBe(`${fixture.tenantId}:org:institution`);
      expect(scopedRules.map((rule) => rule.id)).toContain(created.rule.id);
      expect(siblingRules.map((rule) => rule.id)).not.toContain(created.rule.id);
      expect(updated.status === "updated" ? updated.rule.orgUnitId : null).toBe(course.id);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("allows course org units under departments and programs only", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const { college, department, course, program, programCourse } =
        await createDepartmentCourseOrgUnitHierarchy(fixture.db, {
          tenantId: fixture.tenantId,
          userId: fixture.userId,
          includeProgram: true,
        });

      await expect(
        dbModule.createTenantOrgUnit(fixture.db, {
          tenantId: fixture.tenantId,
          unitType: "course",
          slug: "invalid-course",
          displayName: "Invalid Course",
          parentOrgUnitId: college.id,
          createdByUserId: fixture.userId,
        }),
      ).rejects.toThrow("requires parent org unit type department or program");

      expect(course.parentOrgUnitId).toBe(department.id);
      expect(programCourse?.parentOrgUnitId).toBe(program?.id);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("updates a rejected latest version by creating the next draft version", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await createFixtureRule(fixture);

      await fixture.db
        .prepare("UPDATE badge_issuance_rule_versions SET status = 'rejected' WHERE id = ?")
        .bind(created.version.id)
        .run();

      const result = await dbModule.updateBadgeIssuanceRuleDraft(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        name: "CS101 Rule Revised",
        description: "Updated description.",
        badgeTemplateId: fixture.badgeTemplateId,
        lmsProviderKind: "canvas",
        lmsConnectionId: fixture.lmsConnectionId,
        ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":90}}',
        changeSummary: "Raise score threshold",
        createdByUserId: fixture.userId,
      });

      expect(result.status).toBe("updated");
      expect(result.status === "updated" ? result.version.versionNumber : null).toBe(2);
      expect(result.status === "updated" ? result.version.status : null).toBe("draft");

      const savedRule = await dbModule.findBadgeIssuanceRuleById(
        fixture.db,
        fixture.tenantId,
        created.rule.id,
      );
      const versions = await dbModule.listBadgeIssuanceRuleVersions(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
      });
      const approvalStepCount = await selectCount(
        fixture.db,
        "SELECT COUNT(*) AS totalCount FROM badge_issuance_rule_approval_steps WHERE tenant_id = ?",
        [fixture.tenantId],
      );

      expect(savedRule?.name).toBe("CS101 Rule Revised");
      expect(savedRule?.description).toBe("Updated description.");
      expect(versions).toHaveLength(2);
      expect(versions[0]?.versionNumber).toBe(2);
      expect(approvalStepCount).toBe(0);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("allows active rules to carry an editable latest replacement draft", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await createFixtureRule(fixture);

      await fixture.db
        .prepare(
          `
          UPDATE badge_issuance_rule_versions
          SET status = 'active', activated_by_user_id = ?, activated_at = ?
          WHERE id = ?
        `,
        )
        .bind(fixture.userId, new Date().toISOString(), created.version.id)
        .run();
      await fixture.db
        .prepare("UPDATE badge_issuance_rules SET active_version_id = ? WHERE id = ?")
        .bind(created.version.id, created.rule.id)
        .run();

      const draftVersion = await dbModule.createBadgeIssuanceRuleVersion(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":85}}',
        changeSummary: "Replacement draft",
        createdByUserId: fixture.userId,
      });
      const versionsBeforeUpdate = await dbModule.listBadgeIssuanceRuleVersions(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
      });
      const activeRule = await dbModule.findBadgeIssuanceRuleById(
        fixture.db,
        fixture.tenantId,
        created.rule.id,
      );

      expect(activeRule?.activeVersionId).toBe(created.version.id);
      expect(
        activeRule === null
          ? false
          : dbModule.canEditBadgeIssuanceRuleDraft(activeRule, versionsBeforeUpdate),
      ).toBe(true);

      const result = await dbModule.updateBadgeIssuanceRuleDraft(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        name: "CS101 Replacement",
        badgeTemplateId: fixture.badgeTemplateId,
        lmsProviderKind: "canvas",
        lmsConnectionId: fixture.lmsConnectionId,
        ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":90}}',
        changeSummary: "Raise score threshold",
        createdByUserId: fixture.userId,
      });

      expect(draftVersion.status).toBe("draft");
      expect(result.status).toBe("updated");
      expect(result.status === "updated" ? result.rule.activeVersionId : null).toBe(
        created.version.id,
      );
      expect(result.status === "updated" ? result.version.versionNumber : null).toBe(3);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("blocks pending latest versions without changing metadata", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await createFixtureRule(fixture);

      await fixture.db
        .prepare("UPDATE badge_issuance_rule_versions SET status = 'pending_approval' WHERE id = ?")
        .bind(created.version.id)
        .run();

      const result = await dbModule.updateBadgeIssuanceRuleDraft(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        name: "Should not save",
        badgeTemplateId: fixture.badgeTemplateId,
        lmsProviderKind: "canvas",
        lmsConnectionId: fixture.lmsConnectionId,
        ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":90}}',
        createdByUserId: fixture.userId,
      });

      const savedRule = await dbModule.findBadgeIssuanceRuleById(
        fixture.db,
        fixture.tenantId,
        created.rule.id,
      );
      const versions = await dbModule.listBadgeIssuanceRuleVersions(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
      });

      expect(result.status).toBe("not_editable");
      expect(savedRule?.name).toBe("CS101 Rule");
      expect(versions).toHaveLength(1);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("rolls back metadata updates when badge template ownership cannot be resolved", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await createFixtureRule(fixture);

      await fixture.db
        .prepare("UPDATE badge_issuance_rule_versions SET status = 'rejected' WHERE id = ?")
        .bind(created.version.id)
        .run();

      await expect(
        dbModule.updateBadgeIssuanceRuleDraft(fixture.db, {
          tenantId: fixture.tenantId,
          ruleId: created.rule.id,
          name: "Partially saved name",
          badgeTemplateId: "missing_badge_template",
          lmsProviderKind: "canvas",
          lmsConnectionId: fixture.lmsConnectionId,
          ruleJson:
            '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":90}}',
          createdByUserId: fixture.userId,
        }),
      ).rejects.toThrow('Badge template "missing_badge_template" not found');

      const savedRule = await dbModule.findBadgeIssuanceRuleById(
        fixture.db,
        fixture.tenantId,
        created.rule.id,
      );
      const versions = await dbModule.listBadgeIssuanceRuleVersions(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
      });

      expect(savedRule?.name).toBe("CS101 Rule");
      expect(savedRule?.badgeTemplateId).toBe(fixture.badgeTemplateId);
      expect(versions).toHaveLength(1);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("blocks historical active rules from draft delete", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await createFixtureRule(fixture);

      await fixture.db
        .prepare(
          `
          UPDATE badge_issuance_rule_versions
          SET status = 'active',
              activated_by_user_id = ?,
              activated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `,
        )
        .bind(fixture.userId, created.version.id)
        .run();
      await fixture.db
        .prepare("UPDATE badge_issuance_rules SET active_version_id = ? WHERE id = ?")
        .bind(created.version.id, created.rule.id)
        .run();

      const rejectedVersion = await dbModule.createBadgeIssuanceRuleVersion(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":90}}',
        changeSummary: "Rejected follow-up draft",
        createdByUserId: fixture.userId,
      });

      await fixture.db
        .prepare("UPDATE badge_issuance_rule_versions SET status = 'rejected' WHERE id = ?")
        .bind(rejectedVersion.id)
        .run();

      const result = await dbModule.deleteDraftBadgeIssuanceRule(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
      });
      const ruleCount = await selectCount(
        fixture.db,
        "SELECT COUNT(*) AS totalCount FROM badge_issuance_rules WHERE tenant_id = ? AND id = ?",
        [fixture.tenantId, created.rule.id],
      );
      const versionCount = await selectCount(
        fixture.db,
        "SELECT COUNT(*) AS totalCount FROM badge_issuance_rule_versions WHERE tenant_id = ? AND rule_id = ?",
        [fixture.tenantId, created.rule.id],
      );

      expect(result.status).toBe("not_deletable");
      expect(ruleCount).toBe(1);
      expect(versionCount).toBe(2);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });

  it("deletes never-active draft and rejected rules with real cascade behavior", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const created = await createFixtureRule(fixture);

      await fixture.db
        .prepare("UPDATE badge_issuance_rule_versions SET status = 'rejected' WHERE id = ?")
        .bind(created.version.id)
        .run();

      await dbModule.createBadgeIssuanceRuleVersion(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
        ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":90}}',
        changeSummary: "New draft",
        createdByUserId: fixture.userId,
      });

      const result = await dbModule.deleteDraftBadgeIssuanceRule(fixture.db, {
        tenantId: fixture.tenantId,
        ruleId: created.rule.id,
      });
      const ruleCount = await selectCount(
        fixture.db,
        "SELECT COUNT(*) AS totalCount FROM badge_issuance_rules WHERE tenant_id = ?",
        [fixture.tenantId],
      );
      const versionCount = await selectCount(
        fixture.db,
        "SELECT COUNT(*) AS totalCount FROM badge_issuance_rule_versions WHERE tenant_id = ?",
        [fixture.tenantId],
      );
      const approvalStepCount = await selectCount(
        fixture.db,
        "SELECT COUNT(*) AS totalCount FROM badge_issuance_rule_approval_steps WHERE tenant_id = ?",
        [fixture.tenantId],
      );

      expect(result.status).toBe("deleted");
      expect(ruleCount).toBe(0);
      expect(versionCount).toBe(0);
      expect(approvalStepCount).toBe(0);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });
});

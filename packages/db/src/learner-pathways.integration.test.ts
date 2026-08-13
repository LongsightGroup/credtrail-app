import { expect, it } from "vitest";
import {
  approveLearnerPathwayCompletionReview,
  createLearnerPathwayDraft,
  createLearnerProfile,
  createLearnerRecordEntry,
  createNextLearnerPathwayDraft,
  enrollLearnerInPathway,
  evaluateLearnerPathwayEnrollment,
  findLearnerPathwayById,
  findLearnerPathwayDraft,
  listLearnerPathwayProgress,
  listLearnerPathwayRequirements,
  publishLearnerPathway,
  recordLearnerPathwayFinalCredentialIssuance,
  recordAssertionRevocation,
  retireLearnerPathway,
  revokeLearnerPathwayRequirementWaiver,
  updateLearnerPathwayDraft,
  upsertUserByEmail,
  waiveLearnerPathwayRequirement,
} from "./index";
import {
  cleanupTestResources,
  createTestTenantFixture,
  describeDbIntegration,
  seedAssertion,
  seedBadgeTemplate,
  uniqueTestId,
} from "./postgres-test-support";

describeDbIntegration("governed learner pathways", () => {
  it("preserves published versions and durable evidence decisions through completion and invalidation", async () => {
    const fixture = await createTestTenantFixture({ displayName: "Pathway University" });
    const actor = await upsertUserByEmail(
      fixture.db,
      `${uniqueTestId("pathway_admin")}@example.edu`,
    );

    try {
      const badgeTemplateId = await seedBadgeTemplate(fixture.db, {
        tenantId: fixture.tenantId,
        title: "Research Foundations",
      });
      const finalBadgeTemplateId = await seedBadgeTemplate(fixture.db, {
        tenantId: fixture.tenantId,
        title: "Research Practitioner",
      });
      const learner = await createLearnerProfile(fixture.db, {
        tenantId: fixture.tenantId,
        displayName: "Ada Learner",
        primaryIdentityType: "email",
        primaryIdentityValue: "ada.pathway@example.edu",
        primaryIdentityVerified: true,
      });
      await expect(
        createLearnerPathwayDraft(fixture.db, {
          tenantId: fixture.tenantId,
          ownerOrgUnitId: `${fixture.tenantId}:org:institution`,
          title: "Circular pathway",
          learnerDescription: "A final credential cannot satisfy its own pathway.",
          completionBehavior: "credential_eligible",
          finalBadgeTemplateId,
          actorUserId: actor.id,
          requirements: [
            {
              requirementKind: "badge_template",
              badgeTemplateId: finalBadgeTemplateId,
              title: "Circular final credential",
            },
          ],
        }),
      ).rejects.toThrow("cannot also be one of its pathway requirements");
      const draft = await createLearnerPathwayDraft(fixture.db, {
        tenantId: fixture.tenantId,
        ownerOrgUnitId: `${fixture.tenantId}:org:institution`,
        title: "Applied Research",
        learnerDescription: "Build and demonstrate a governed research practice.",
        completionBehavior: "credential_eligible",
        finalBadgeTemplateId,
        actorUserId: actor.id,
        requirements: [
          {
            requirementKind: "badge_template",
            badgeTemplateId,
            title: "Research Foundations",
          },
          {
            requirementKind: "learner_record",
            learnerRecordType: "course",
            title: "Verified research course",
          },
        ],
      });

      await publishLearnerPathway(fixture.db, {
        tenantId: fixture.tenantId,
        pathwayId: draft.id,
        actorUserId: actor.id,
      });
      const enrollmentId = await enrollLearnerInPathway(fixture.db, {
        tenantId: fixture.tenantId,
        pathwayId: draft.id,
        learnerProfileId: learner.id,
        actorUserId: actor.id,
      });

      await createLearnerRecordEntry(fixture.db, {
        tenantId: fixture.tenantId,
        learnerProfileId: learner.id,
        trustLevel: "learner_supplemental",
        recordType: "course",
        title: "Self-reported research course",
        issuerName: "Learner",
        sourceSystem: "learner_self_reported",
        issuedAt: "2026-08-01T10:00:00.000Z",
        evidenceLinks: [],
      });
      const supplementalEvaluation = await evaluateLearnerPathwayEnrollment(fixture.db, {
        tenantId: fixture.tenantId,
        enrollmentId,
        trigger: "supplemental_evidence",
      });
      expect(supplementalEvaluation.requirements[1]?.state).toBe("not_recorded");

      await createLearnerRecordEntry(fixture.db, {
        tenantId: fixture.tenantId,
        learnerProfileId: learner.id,
        trustLevel: "issuer_verified",
        recordType: "course",
        title: "Research Methods",
        issuerName: "Pathway University",
        sourceSystem: "credtrail_admin",
        issuedAt: "2026-08-02T10:00:00.000Z",
        evidenceLinks: [],
      });
      const assertionId = await seedAssertion(fixture.db, {
        tenantId: fixture.tenantId,
        learnerProfileId: learner.id,
        badgeTemplateId,
        recipientIdentity: "ada.pathway@example.edu",
        issuedAt: "2026-08-03T10:00:00.000Z",
      });
      const complete = await evaluateLearnerPathwayEnrollment(fixture.db, {
        tenantId: fixture.tenantId,
        enrollmentId,
        trigger: "assertion_issued",
      });
      expect(complete.result).toBe("complete");
      expect(complete.qualifyingEvidenceIds).toContain(assertionId);

      let progress = await listLearnerPathwayProgress(fixture.db, {
        tenantId: fixture.tenantId,
        learnerProfileId: learner.id,
      });
      expect(progress[0]?.state._tag).toBe("eligible");
      expect(progress[0]?.completedAt).not.toBeNull();

      await recordAssertionRevocation(fixture.db, {
        tenantId: fixture.tenantId,
        assertionId,
        revocationId: uniqueTestId("rev"),
        reason: "Evidence withdrawn",
        idempotencyKey: uniqueTestId("idem"),
        revokedByUserId: actor.id,
        revokedAt: "2026-08-04T10:00:00.000Z",
      });
      const invalidated = await evaluateLearnerPathwayEnrollment(fixture.db, {
        tenantId: fixture.tenantId,
        enrollmentId,
        trigger: "assertion_revoked",
      });
      expect(invalidated.result).toBe("invalidated");

      progress = await listLearnerPathwayProgress(fixture.db, {
        tenantId: fixture.tenantId,
        learnerProfileId: learner.id,
      });
      expect(progress[0]?.state._tag).toBe("invalidated");
      expect(progress[0]?.completedAt).not.toBeNull();
      expect(progress[0]?.evaluationHistory.map((entry) => entry.result)).toContain("complete");

      const requirements = await listLearnerPathwayRequirements(
        fixture.db,
        fixture.tenantId,
        draft.version.id,
      );
      await waiveLearnerPathwayRequirement(fixture.db, {
        tenantId: fixture.tenantId,
        pathwayId: draft.id,
        enrollmentId,
        requirementId: requirements[0]?.id ?? "missing",
        reason: "Academic review accepted equivalent verified evidence.",
        actorUserId: actor.id,
      });
      const waivedProgress = await listLearnerPathwayProgress(fixture.db, {
        tenantId: fixture.tenantId,
        learnerProfileId: learner.id,
      });
      expect(waivedProgress[0]?.evaluation.result).toBe("complete");
      expect(waivedProgress[0]?.evaluation.requirements[0]?.state).toBe("waived");
      expect(waivedProgress[0]?.evaluation.requirements[0]?.rationale).toContain(
        "Academic review accepted",
      );

      await revokeLearnerPathwayRequirementWaiver(fixture.db, {
        tenantId: fixture.tenantId,
        pathwayId: draft.id,
        enrollmentId,
        requirementId: requirements[0]?.id ?? "missing",
        actorUserId: actor.id,
      });
      const revokedWaiverProgress = await listLearnerPathwayProgress(fixture.db, {
        tenantId: fixture.tenantId,
        learnerProfileId: learner.id,
      });
      expect(revokedWaiverProgress[0]?.evaluation.result).toBe("invalidated");
      expect(revokedWaiverProgress[0]?.evaluation.requirements[0]?.state).toBe("invalidated");
      expect(revokedWaiverProgress[0]?.state._tag).toBe("invalidated");

      await expect(
        fixture.db
          .prepare("UPDATE learner_pathway_versions SET title = ? WHERE tenant_id = ? AND id = ?")
          .bind("Rewritten history", fixture.tenantId, draft.version.id)
          .run(),
      ).rejects.toThrow("published pathway versions are immutable");

      const nextDraft = await createNextLearnerPathwayDraft(fixture.db, {
        tenantId: fixture.tenantId,
        pathwayId: draft.id,
        actorUserId: actor.id,
      });
      await updateLearnerPathwayDraft(fixture.db, {
        tenantId: fixture.tenantId,
        pathwayId: draft.id,
        ownerOrgUnitId: `${fixture.tenantId}:org:institution`,
        title: "Applied Research II",
        learnerDescription: "A revised program that does not rewrite prior enrollments.",
        completionBehavior: "mark_complete",
        actorUserId: actor.id,
        requirements: [
          {
            requirementKind: "learner_record",
            learnerRecordType: "competency",
            title: "Verified research competency",
          },
        ],
      });
      await publishLearnerPathway(fixture.db, {
        tenantId: fixture.tenantId,
        pathwayId: draft.id,
        actorUserId: actor.id,
      });
      const current = await findLearnerPathwayById(fixture.db, fixture.tenantId, draft.id);
      const remainingDraft = await findLearnerPathwayDraft(fixture.db, fixture.tenantId, draft.id);
      expect(nextDraft.version.number).toBe(2);
      expect(current?.version.title).toBe("Applied Research II");
      expect(remainingDraft).toBeNull();
      expect(waivedProgress[0]?.pathwayVersionId).toBe(draft.version.id);

      const reviewPathway = await createLearnerPathwayDraft(fixture.db, {
        tenantId: fixture.tenantId,
        ownerOrgUnitId: `${fixture.tenantId}:org:institution`,
        title: "Reviewed Research Credential",
        learnerDescription: "Require a human decision before final credential issuance.",
        completionBehavior: "review_required",
        finalBadgeTemplateId,
        actorUserId: actor.id,
        requirements: [
          {
            requirementKind: "learner_record",
            learnerRecordType: "course",
            title: "Verified research course",
          },
        ],
      });
      await publishLearnerPathway(fixture.db, {
        tenantId: fixture.tenantId,
        pathwayId: reviewPathway.id,
        actorUserId: actor.id,
      });
      const reviewEnrollmentId = await enrollLearnerInPathway(fixture.db, {
        tenantId: fixture.tenantId,
        pathwayId: reviewPathway.id,
        learnerProfileId: learner.id,
        actorUserId: actor.id,
      });
      let reviewProgress = await listLearnerPathwayProgress(fixture.db, {
        tenantId: fixture.tenantId,
        learnerProfileId: learner.id,
      });
      expect(reviewProgress.find((entry) => entry.pathwayId === reviewPathway.id)?.state._tag).toBe(
        "needs_review",
      );
      await approveLearnerPathwayCompletionReview(fixture.db, {
        tenantId: fixture.tenantId,
        pathwayId: reviewPathway.id,
        enrollmentId: reviewEnrollmentId,
        actorUserId: actor.id,
      });
      reviewProgress = await listLearnerPathwayProgress(fixture.db, {
        tenantId: fixture.tenantId,
        learnerProfileId: learner.id,
      });
      expect(reviewProgress.find((entry) => entry.pathwayId === reviewPathway.id)?.state._tag).toBe(
        "eligible",
      );
      const finalCredentialAssertion = await fixture.db
        .prepare(
          `SELECT id FROM assertions
           WHERE tenant_id = ? AND learner_profile_id = ? AND badge_template_id = ? LIMIT 1`,
        )
        .bind(fixture.tenantId, learner.id, finalBadgeTemplateId)
        .first<{ id: string }>();
      expect(finalCredentialAssertion).toBeNull();

      const finalAssertionPublicId = crypto.randomUUID();
      const issuedFinalAssertionId = await seedAssertion(fixture.db, {
        tenantId: fixture.tenantId,
        learnerProfileId: learner.id,
        badgeTemplateId: finalBadgeTemplateId,
        publicId: finalAssertionPublicId,
        recipientIdentity: "ada.pathway@example.edu",
        issuedAt: "2026-08-06T10:00:00.000Z",
      });
      const eligibleState = reviewProgress.find(
        (entry) => entry.pathwayId === reviewPathway.id,
      )?.state;
      expect(eligibleState?._tag).toBe("eligible");
      if (eligibleState?._tag !== "eligible") {
        throw new Error("Expected reviewed pathway to be eligible for issuance");
      }
      const unrelatedHandoffRecorded = await recordLearnerPathwayFinalCredentialIssuance(
        fixture.db,
        {
          tenantId: fixture.tenantId,
          handoffId: uniqueTestId("unrelated_handoff"),
          learnerProfileId: learner.id,
          badgeTemplateId: finalBadgeTemplateId,
          assertionId: issuedFinalAssertionId,
          actorUserId: actor.id,
          issuedAt: "2026-08-06T10:00:00.000Z",
        },
      );
      expect(unrelatedHandoffRecorded).toBe(false);
      const exactHandoffRecorded = await recordLearnerPathwayFinalCredentialIssuance(fixture.db, {
        tenantId: fixture.tenantId,
        handoffId: eligibleState.handoffId,
        learnerProfileId: learner.id,
        badgeTemplateId: finalBadgeTemplateId,
        assertionId: issuedFinalAssertionId,
        actorUserId: actor.id,
        issuedAt: "2026-08-06T10:00:00.000Z",
      });
      expect(exactHandoffRecorded).toBe(true);
      reviewProgress = await listLearnerPathwayProgress(fixture.db, {
        tenantId: fixture.tenantId,
        learnerProfileId: learner.id,
      });
      const issuedState = reviewProgress.find(
        (entry) => entry.pathwayId === reviewPathway.id,
      )?.state;
      expect(issuedState?._tag).toBe("issued");
      expect(issuedState?._tag === "issued" ? issuedState.assertionPublicId : null).toBe(
        finalAssertionPublicId,
      );

      await evaluateLearnerPathwayEnrollment(fixture.db, {
        tenantId: fixture.tenantId,
        enrollmentId: reviewEnrollmentId,
        trigger: "evidence_changed_after_issuance",
      });
      const progressAfterReevaluation = await listLearnerPathwayProgress(fixture.db, {
        tenantId: fixture.tenantId,
        learnerProfileId: learner.id,
      });
      const issuedProgressAfterReevaluation = progressAfterReevaluation.find(
        (entry) => entry.pathwayId === reviewPathway.id,
      );
      expect(issuedProgressAfterReevaluation?.state._tag).toBe("issued");
      expect(issuedProgressAfterReevaluation?.enrollmentStatus).toBe("completed");
      const handoffCount = await fixture.db
        .prepare(
          `SELECT COUNT(*) AS count
           FROM learner_pathway_completion_handoffs
           WHERE tenant_id = ? AND enrollment_id = ?`,
        )
        .bind(fixture.tenantId, reviewEnrollmentId)
        .first<{ count: number | string }>();
      expect(Number(handoffCount?.count ?? 0)).toBe(1);

      await retireLearnerPathway(fixture.db, {
        tenantId: fixture.tenantId,
        pathwayId: draft.id,
        actorUserId: actor.id,
      });
      await expect(
        enrollLearnerInPathway(fixture.db, {
          tenantId: fixture.tenantId,
          pathwayId: draft.id,
          learnerProfileId: learner.id,
          actorUserId: actor.id,
        }),
      ).rejects.toThrow("published pathway");
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [actor.id],
      });
    }
  });
});

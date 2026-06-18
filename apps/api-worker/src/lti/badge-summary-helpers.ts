import type { AssertionRecord, BadgeTemplateRecord } from "@credtrail/db";
import { badgeTemplateCriteriaRegistryHref } from "../badges/badge-template-public-links";
import { asNonEmptyString } from "../utils/value-parsers";
import type { LtiBadgeSummaryCard, LtiBadgeSummaryStatus } from "./view-models";

export const LTI_BADGE_QUALIFICATION_SUMMARY_FALLBACK =
  "Open criteria to review how learners qualify for this badge.";

export const LTI_ACTIVE_BADGE_SUMMARY_STATUS: LtiBadgeSummaryStatus = {
  label: "Active",
  modifier: "active",
};

export const ltiBadgeTemplateSummary = (badgeTemplate: BadgeTemplateRecord): string => {
  return asNonEmptyString(badgeTemplate.description) ?? LTI_BADGE_QUALIFICATION_SUMMARY_FALLBACK;
};

export const ltiBadgeSummaryCardFromTemplate = (input: {
  tenantId: string;
  badgeTemplate: BadgeTemplateRecord;
}): LtiBadgeSummaryCard => {
  return {
    badgeTemplateId: input.badgeTemplate.id,
    title: input.badgeTemplate.title,
    summary: ltiBadgeTemplateSummary(input.badgeTemplate),
    imageUri: input.badgeTemplate.imageUri,
    criteriaPath: badgeTemplateCriteriaRegistryHref(input.tenantId, input.badgeTemplate.id),
  };
};

export const newestByIssuedAt = <T>(
  current: T | undefined,
  candidate: T,
  input: {
    issuedAt: (value: T) => string;
    id: (value: T) => string;
  },
): T => {
  if (current === undefined) {
    return candidate;
  }

  const currentIssuedAtValue = input.issuedAt(current);
  const candidateIssuedAtValue = input.issuedAt(candidate);
  const currentIssuedAt = Date.parse(currentIssuedAtValue);
  const candidateIssuedAt = Date.parse(candidateIssuedAtValue);

  if (Number.isFinite(candidateIssuedAt) && Number.isFinite(currentIssuedAt)) {
    if (candidateIssuedAt !== currentIssuedAt) {
      return candidateIssuedAt > currentIssuedAt ? candidate : current;
    }
  } else if (Number.isFinite(candidateIssuedAt)) {
    return candidate;
  } else if (Number.isFinite(currentIssuedAt)) {
    return current;
  } else if (candidateIssuedAtValue !== currentIssuedAtValue) {
    return candidateIssuedAtValue > currentIssuedAtValue ? candidate : current;
  }

  return input.id(candidate) > input.id(current) ? candidate : current;
};

export const newestAssertion = (
  current: AssertionRecord | undefined,
  candidate: AssertionRecord,
): AssertionRecord => {
  return newestByIssuedAt(current, candidate, {
    issuedAt: (assertion) => assertion.issuedAt,
    id: (assertion) => assertion.id,
  });
};

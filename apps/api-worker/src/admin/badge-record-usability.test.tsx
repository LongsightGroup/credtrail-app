import { appPage, renderAppPageToString } from "../ui/render-page";
import { expect, it } from "vitest";
import type { AssertionLifecycleState, TenantAssertionSummaryRecord } from "@credtrail/db";
import { IssuedBadgeRows } from "./components";
import { IssuanceNotification } from "./issuance-notification";
import { learnerRecordLink } from "./learner-record-link";

const assertion: TenantAssertionSummaryRecord = {
  assertionId: "assertion_1",
  tenantId: "tenant_1",
  publicId: "public_1",
  badgeTemplateId: "badge_1",
  badgeTitle: "Analytics",
  badgeImageUri: null,
  recipientIdentity: "learner+course@example.edu",
  recipientIdentityType: "email",
  issuedAt: "2026-09-17T12:00:00.000Z",
  issuedByUserId: null,
  revokedAt: null,
  state: "active",
  source: "default_active",
  reasonCode: null,
  reason: null,
  transitionedAt: null,
};

it.each<[AssertionLifecycleState, string]>([
  ["active", "Active"],
  ["suspended", "Suspended"],
  ["revoked", "Revoked"],
  ["expired", "Expired"],
])("renders %s with the correct readable status", (state, label) => {
  const html = (
    <IssuedBadgeRows
      assertions={[{ ...assertion, state }]}
      evidenceHrefForAssertion={() => "/record"}
      statusHrefForAssertion={() => "/status"}
    />
  );
  expect(renderAppPageToString(appPage({ title: "Test", body: html }))).toContain(
    `>${label}</span>`,
  );
  expect(renderAppPageToString(appPage({ title: "Test", body: html }))).toContain(
    "learner%2Bcourse%40example.edu",
  );
});

it("does not send unsupported recipient identities to email lookup", () => {
  expect(learnerRecordLink("tenant_1", "did", "did:example:123")).toBeNull();
});

it.each(["failed", "disabled", "not_configured"] as const)(
  "places sharing recovery with the %s notification",
  (outcome) => {
    const html = (
      <IssuanceNotification
        outcome={outcome}
        publicBadgeUrl="https://credtrail.org/badges/public_1"
      />
    );
    expect(renderAppPageToString(appPage({ title: "Test", body: html }))).toContain(
      "Share this link with the learner.",
    );
    expect(renderAppPageToString(appPage({ title: "Test", body: html }))).toContain(
      'data-public-badge-url="https://credtrail.org/badges/public_1"',
    );
    expect(renderAppPageToString(appPage({ title: "Test", body: html }))).toContain(
      "Copy public badge link",
    );
  },
);

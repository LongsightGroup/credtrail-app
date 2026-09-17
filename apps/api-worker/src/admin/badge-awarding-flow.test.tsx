import type { BadgeTemplateRecord } from "@credtrail/db";
import type { ImmutableCredentialStore } from "@credtrail/core-domain";
import { describe, expect, it } from "vitest";
import { BadgePreparationActions } from "./badge-preparation-actions";
import { resolveManualIssueSelection } from "./manual-issue-selection";
import { issuePreparedBadgePath, automaticBadgeAwardingPath } from "./badge-awarding-links";
import { renderManualIssueSection } from "./institution-admin/manual-issue-section";
import { appPage, renderAppPageToString } from "../ui/render-page";

const template: BadgeTemplateRecord = {
  id: "template_123",
  tenantId: "tenant_123",
  slug: "analytics",
  title: "Applied Analytics",
  description: null,
  criteriaUri: null,
  imageUri: "https://credtrail.org/badges/assets/tenant_123/template_123/asset_456",
  createdByUserId: "user_123",
  ownerOrgUnitId: "org_123",
  governanceMetadataJson: null,
  isArchived: false,
  createdAt: "2026-09-16T12:00:00.000Z",
  updatedAt: "2026-09-16T12:00:00.000Z",
};
const storedImage = JSON.stringify({
  version: 1,
  mimeType: "image/png",
  byteSize: 8,
  base64Data: "iVBORw0KGgo=",
  uploadedAt: "2026-09-16T12:00:00.000Z",
  originalFilename: "badge.png",
});
const store: ImmutableCredentialStore = {
  head: async () => null,
  get: async () => ({
    size: new TextEncoder().encode(storedImage).byteLength,
    text: async () => storedImage,
  }),
  put: async () => null,
  delete: async () => {},
};
const render = (body: Parameters<typeof appPage>[0]["body"]): string =>
  renderAppPageToString(appPage({ title: "Badge awarding", body }));
const select = (
  query: unknown,
  templates: readonly BadgeTemplateRecord[] = [template],
  imageStore = store,
) =>
  resolveManualIssueSelection({
    query,
    templates,
    store: imageStore,
    publicAppOrigin: "https://credtrail.org",
  });

describe("badge preparation to awarding", () => {
  it("offers both handoffs only after preparation", () => {
    const html = render(<BadgePreparationActions template={template} readiness="ready" />);
    expect(html).toContain(`href="${issuePreparedBadgePath(template.tenantId, template.id)}"`);
    expect(html).toContain(`href="${automaticBadgeAwardingPath(template.tenantId, template.id)}"`);
    expect(html).toContain("approved and activated");
  });
  it.each([
    "missing_artwork",
    "unmanaged_artwork",
    "invalid_artwork",
    "storage_unavailable",
  ] as const)("keeps awarding unavailable for %s", (readiness) => {
    const html = render(<BadgePreparationActions template={template} readiness={readiness} />);
    expect(html).not.toContain("Issue this badge");
    expect(html).not.toContain("Set up automatic awarding");
  });
  it("keeps archived badges out of awarding", () => {
    expect(
      render(
        <BadgePreparationActions template={{ ...template, isArchived: true }} readiness="ready" />,
      ),
    ).not.toContain("Issue this badge");
  });
  it("preselects a verified badge and asks only for its recipient", async () => {
    const resolved = await select({ badgeTemplateId: template.id });
    expect(resolved.selection.kind).toBe("ready");
    const html = render(
      <>
        {renderManualIssueSection({
          issuanceRequestId: "1f016e84-49df-41c8-b560-e331d7d94223",
          tenantId: template.tenantId,
          hasReadyTemplates: true,
          selection: resolved.selection,
          templateSelectOptions: [],
          pathwayHandoffId: null,
        })}
      </>,
    );
    expect(html).toContain("Applied Analytics");
    expect(html).toContain(template.imageUri);
    expect(html).toContain("<details><summary>Change badge</summary>");
    expect(html).toContain('<select name="badgeTemplateId"');
    expect(html).toContain("Recipient email");
    expect(html).toContain("Change badge");
    expect(html).not.toContain("<details open");
  });
  it.each([
    { templates: [] },
    { templates: [{ ...template, isArchived: true }] },
    { templates: [{ ...template, id: "other_template" }] },
  ])("rejects missing, archived, and out-of-scope badge selections", async ({ templates }) => {
    const result = await select({ badgeTemplateId: template.id }, templates);
    expect(result.selection).toMatchObject({ kind: "blocked", template: null });
  });
  it("requires actual stored artwork, not merely an image URL", async () => {
    const result = await select({ badgeTemplateId: template.id }, [template], {
      ...store,
      get: async () => null,
    });
    expect(result.selection).toMatchObject({
      kind: "blocked",
      message: "Add artwork before issuing this badge.",
    });
    const html = render(
      <>
        {renderManualIssueSection({
          issuanceRequestId: "1f016e84-49df-41c8-b560-e331d7d94223",
          tenantId: template.tenantId,
          hasReadyTemplates: true,
          selection: result.selection,
          templateSelectOptions: [],
        })}
      </>,
    );
    expect(html).toContain("Prepare badge");
    expect(html).not.toContain('id="manual-issue-form"');
  });
  it("preserves governed pathway context and prevents changing its badge", async () => {
    const resolved = await select({
      badgeTemplateId: template.id,
      pathwayHandoffId: "handoff_123",
    });
    const html = render(
      <>
        {renderManualIssueSection({
          issuanceRequestId: "1f016e84-49df-41c8-b560-e331d7d94223",
          tenantId: template.tenantId,
          hasReadyTemplates: true,
          selection: resolved.selection,
          pathwayHandoffId: resolved.pathwayHandoffId,
          templateSelectOptions: [],
        })}
      </>,
    );
    expect(html).toContain('value="handoff_123"');
    expect(html).not.toContain("Change badge");
  });
  it("does not silently discard an invalid handoff", async () => {
    expect((await select({ pathwayHandoffId: "handoff_123" })).selection.kind).toBe("blocked");
    expect((await select({ badgeTemplateId: "" })).selection.kind).toBe("blocked");
  });
});

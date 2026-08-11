import { appPage, type AppPage } from "../ui/render-page";
import {
  badgeTemplateCriteriaRegistryHref,
  badgeTemplateShowcaseHref,
  tenantBadgeCriteriaRegistryHref,
} from "./badge-template-public-links";
import { buildSeoHeadContent, resolveAbsoluteWebUrl } from "./public-badge-renderer-helpers";
import type {
  CreatePublicBadgePageRenderersInput,
  PublicBadgeCriteriaRegistryViewModel,
  PublicBadgePageRenderers,
} from "./public-badge-renderer-types";
import { createRuleDefinitionSummaryMarkup } from "./badge-rule-definition-summary";

type ApprovalStepStatus = "approved" | "pending" | "queued" | "rejected" | "changes_requested";

const humanizeApprovalStepStatus = (status: ApprovalStepStatus): string => {
  switch (status) {
    case "approved":
      return "Approved";
    case "rejected":
      return "Rejected";
    case "changes_requested":
      return "Changes requested";
    case "pending":
      return "Pending";
    case "queued":
      return "Queued";
    default:
      return status;
  }
};

const isGenericApprovalStepLabel = (label: string): boolean => {
  return label === "Administrative approval" || /^Step \d+$/.test(label);
};

export const createTenantBadgeCriteriaRegistryPage = (
  input: CreatePublicBadgePageRenderersInput,
): PublicBadgePageRenderers["tenantBadgeCriteriaRegistryPage"] => {
  const { formatIsoTimestamp, isWebUrl } = input;
  const ruleDefinitionSummaryMarkup = createRuleDefinitionSummaryMarkup(formatIsoTimestamp);
  const toAbsoluteWebUrl = (requestUrl: string, value: string | null): string | null => {
    return resolveAbsoluteWebUrl({ requestUrl, value, isWebUrl });
  };

  return (
    requestUrl: string,
    tenantId: string,
    model: PublicBadgeCriteriaRegistryViewModel,
    filterBadgeTemplateId: string | null,
  ): AppPage => {
    const title = `Badge Criteria Registry · ${tenantId}`;
    const criteriaRegistryPath =
      filterBadgeTemplateId === null
        ? tenantBadgeCriteriaRegistryHref(tenantId)
        : badgeTemplateCriteriaRegistryHref(tenantId, filterBadgeTemplateId);
    const canonicalUrl = new URL(criteriaRegistryPath, requestUrl).toString();
    const subtitle =
      filterBadgeTemplateId === null
        ? `Public criteria and governance metadata for badge templates under tenant "${tenantId}".`
        : `Public criteria and governance metadata for tenant "${tenantId}" badge template "${filterBadgeTemplateId}".`;
    const heroLead =
      filterBadgeTemplateId === null
        ? "Use this page to understand what each public badge recognizes, who publishes it, and how qualification rules are reviewed."
        : "Use this page to understand what this public badge recognizes, who publishes it, and how qualification rules are reviewed.";
    const badgeWallPath =
      filterBadgeTemplateId === null
        ? `/showcase/${encodeURIComponent(tenantId)}`
        : `/showcase/${encodeURIComponent(tenantId)}?badgeTemplateId=${encodeURIComponent(
            filterBadgeTemplateId,
          )}`;
    const orgUnitById = new Map(model.orgUnits.map((orgUnit) => [orgUnit.id, orgUnit]));
    const templateCards =
      model.templates.length === 0 ? (
        <p class="criteria-registry__empty">No public badge templates matched this view.</p>
      ) : (
        model.templates.map((entry) => {
          const template = entry.template;
          const ownerOrgUnit = entry.ownerOrgUnit;
          const ownerLabel =
            ownerOrgUnit === null
              ? template.ownerOrgUnitId
              : `${ownerOrgUnit.displayName} (${ownerOrgUnit.unitType})`;
          const templateShowcasePath = badgeTemplateShowcaseHref(tenantId, template.id);
          const criteriaLink =
            template.criteriaUri === null ? (
              <span class="criteria-registry__muted">
                No public criteria link is published for this badge.
              </span>
            ) : (
              <a href={template.criteriaUri} target="_blank" rel="noopener noreferrer">
                {template.criteriaUri}
              </a>
            );
          const ownershipTransferEvents = entry.ownershipEvents.filter((event) => {
            return event.reasonCode !== "initial_assignment";
          });
          const ownershipTransferHistoryMarkup =
            ownershipTransferEvents.length === 0 ? null : (
              <>
                <p>
                  <strong>Ownership transfer history</strong>
                </p>
                <ol class="criteria-registry__timeline">
                  {ownershipTransferEvents.map((event) => {
                    const fromOrgUnit =
                      event.fromOrgUnitId === null
                        ? null
                        : (orgUnitById.get(event.fromOrgUnitId) ?? null);
                    const toOrgUnit = orgUnitById.get(event.toOrgUnitId) ?? null;
                    const fromLabel =
                      fromOrgUnit === null ? "No previous owner recorded" : fromOrgUnit.displayName;
                    const toLabel = toOrgUnit === null ? event.toOrgUnitId : toOrgUnit.displayName;
                    const actor = event.transferredByUserId ?? "system";
                    const reason =
                      event.reason === null
                        ? event.reasonCode
                        : `${event.reasonCode}: ${event.reason}`;

                    return (
                      <li key={`${event.toOrgUnitId}:${event.transferredAt}`}>
                        <p>
                          <strong>{fromLabel}</strong> → <strong>{toLabel}</strong>
                        </p>
                        <p class="criteria-registry__muted">
                          Why it changed: {reason} · Recorded by {actor} ·{" "}
                          {formatIsoTimestamp(event.transferredAt)} UTC
                        </p>
                      </li>
                    );
                  })}
                </ol>
              </>
            );
          const templateRecordDetails = (
            <details class="criteria-registry__details">
              <summary>
                {template.governanceMetadataJson === null
                  ? "Badge record details"
                  : "Badge record details and raw metadata"}
              </summary>
              <div class="criteria-registry__details-body criteria-registry__stack-sm">
                <p class="criteria-registry__muted">Template ID: {template.id}</p>
                {ownershipTransferHistoryMarkup}
              </div>
              {template.governanceMetadataJson === null ? null : (
                <pre class="criteria-registry__pre">{template.governanceMetadataJson}</pre>
              )}
            </details>
          );
          const rulesSection =
            entry.rules.length === 0 ? (
              <p class="criteria-registry__muted">
                No published qualification rules are available for this badge yet.
              </p>
            ) : (
              entry.rules.map((ruleEntry) => {
                const latestVersion = ruleEntry.latestVersion;
                const activeVersion = ruleEntry.activeVersion;
                const effectiveVersion = activeVersion ?? latestVersion;
                const latestVersionLabel =
                  latestVersion === null
                    ? "No recorded version"
                    : `v${String(latestVersion.versionNumber)} (${latestVersion.status})`;
                const activeVersionLabel =
                  activeVersion === null
                    ? "No published version"
                    : `v${String(activeVersion.versionNumber)}`;
                const changeSummary =
                  effectiveVersion?.changeSummary === null ||
                  effectiveVersion?.changeSummary === undefined ? (
                    <span class="criteria-registry__muted">
                      No public summary was provided for the latest rule update.
                    </span>
                  ) : (
                    effectiveVersion.changeSummary
                  );
                const approvalStepsMarkup =
                  ruleEntry.approvalSteps.length === 0 ? (
                    <p class="criteria-registry__muted">
                      No review steps are published for this rule version.
                    </p>
                  ) : (
                    <ol class="criteria-registry__approval-steps">
                      {ruleEntry.approvalSteps.map((step) => {
                        const actor = step.decidedByUserId ?? "pending";
                        const decidedAt =
                          step.decidedAt === null
                            ? "Awaiting decision"
                            : `${formatIsoTimestamp(step.decidedAt)} UTC`;
                        const reviewLabel =
                          step.label === null || step.label.trim().length === 0
                            ? `Step ${String(step.stepNumber)}`
                            : step.label;
                        const isDecided = step.status === "approved" || step.status === "rejected";
                        const headline = isDecided
                          ? humanizeApprovalStepStatus(step.status)
                          : reviewLabel;
                        const showStepLabelInDetails =
                          ruleEntry.approvalSteps.length > 1 ||
                          !isGenericApprovalStepLabel(reviewLabel);

                        return (
                          <li key={step.id}>
                            <p>
                              <strong>{headline}</strong>
                            </p>
                            <p class="criteria-registry__muted">
                              {showStepLabelInDetails ? `${reviewLabel} · ` : ""}
                              Required role: {step.requiredRole} · Reviewed by {actor} · {decidedAt}
                            </p>
                          </li>
                        );
                      })}
                    </ol>
                  );
                const approvalEventsMarkup =
                  ruleEntry.approvalEvents.length === 0 ? (
                    <p class="criteria-registry__muted">
                      No detailed approval history is published for this rule version.
                    </p>
                  ) : (
                    <ol class="criteria-registry__approval-events">
                      {ruleEntry.approvalEvents.map((event) => {
                        const actor = event.actorUserId ?? "system";
                        const role = event.actorRole ?? "unknown_role";

                        return (
                          <li key={`${event.action}:${event.occurredAt}`}>
                            {event.action} by {actor} ({role}) ·{" "}
                            {formatIsoTimestamp(event.occurredAt)} UTC
                            {event.comment === null ? "" : ` · ${event.comment}`}
                          </li>
                        );
                      })}
                    </ol>
                  );
                const ruleGovernanceDetails = (
                  <details class="criteria-registry__details">
                    <summary>Rule history and governance details</summary>
                    <div class="criteria-registry__details-body criteria-registry__stack-sm">
                      <p class="criteria-registry__muted">Rule ID: {ruleEntry.rule.id}</p>
                      <p class="criteria-registry__muted">
                        Source system: {effectiveVersion?.snapshot.lmsProviderKind ?? "unknown"}
                      </p>
                      <p class="criteria-registry__muted">
                        Current published version: {activeVersionLabel} · Most recent recorded
                        version: {latestVersionLabel}
                      </p>
                      <p>
                        <strong>Review steps</strong>
                      </p>
                      {approvalStepsMarkup}
                      <p>
                        <strong>Detailed approval history</strong>
                      </p>
                      {approvalEventsMarkup}
                    </div>
                  </details>
                );

                return (
                  <article class="criteria-registry__rule" key={ruleEntry.rule.id}>
                    <header>
                      <h3>{effectiveVersion?.snapshot.name ?? "Qualification rule"}</h3>
                      <p class="criteria-registry__muted">
                        This published rule explains when a learner qualifies for this badge.
                      </p>
                    </header>
                    <div class="criteria-registry__stack-sm">
                      <p>
                        <strong>Learners qualify when these checks are met</strong>
                      </p>
                      {ruleDefinitionSummaryMarkup(effectiveVersion?.ruleJson ?? null)}
                      <p>
                        <strong>Latest published update</strong>
                      </p>
                      <p class="criteria-registry__muted">{changeSummary}</p>
                      {ruleGovernanceDetails}
                    </div>
                  </article>
                );
              })
            );

          return (
            <article class="criteria-registry__template-card" key={template.id}>
              <header class="criteria-registry__template-header">
                {template.imageUri === null ? (
                  <span
                    class="criteria-registry__template-image criteria-registry__template-image--placeholder"
                    aria-hidden="true"
                  >
                    B
                  </span>
                ) : (
                  <img
                    class="criteria-registry__template-image"
                    src={template.imageUri}
                    alt={template.title}
                    loading="lazy"
                  />
                )}
                <div class="criteria-registry__template-meta">
                  <h2>{template.title}</h2>
                </div>
              </header>
              <p class="criteria-registry__description">
                {template.description ?? "No public description is published for this badge yet."}
              </p>
              <dl class="criteria-registry__facts">
                <div class="criteria-registry__fact">
                  <dt>Published criteria</dt>
                  <dd>{criteriaLink}</dd>
                </div>
                <div class="criteria-registry__fact">
                  <dt>Current badge owner</dt>
                  <dd>{ownerLabel}</dd>
                </div>
                <div class="criteria-registry__fact">
                  <dt>Registry updated</dt>
                  <dd>{formatIsoTimestamp(template.updatedAt)} UTC</dd>
                </div>
              </dl>
              <p class="criteria-registry__actions">
                <a href={templateShowcasePath}>View public badge examples</a>
              </p>
              <section class="criteria-registry__section">
                <h3>How someone qualifies</h3>
                <p class="criteria-registry__muted">
                  These published rules explain how a learner becomes eligible for this badge.
                </p>
                {rulesSection}
              </section>
              <section class="criteria-registry__section">
                <h3>Governance and ownership</h3>
                <p class="criteria-registry__muted">
                  Current ownership is listed above. Expand record details for template identifiers,
                  ownership transfer history, and published metadata.
                </p>
                {templateRecordDetails}
              </section>
            </article>
          );
        })
      );
    const pageTitle = `${title} | CredTrail`;
    const socialImageUrl =
      model.templates
        .map((entry) => toAbsoluteWebUrl(requestUrl, entry.template.imageUri))
        .find((value): value is string => value !== null) ?? null;

    return appPage({
      title: pageTitle,
      head: buildSeoHeadContent({
        title: pageTitle,
        description: subtitle,
        canonicalUrl,
        ogType: "website",
        imageUrl: socialImageUrl,
      }),
      assets: ["publicBadgeCss"],
      variant: "open",
      body: (
        <section class="criteria-registry">
          <header class="criteria-registry__hero">
            <h1>{title}</h1>
            <p>{heroLead}</p>
            <a class="criteria-registry__hero-link" href={badgeWallPath}>
              Back to badge wall
            </a>
          </header>
          <div class="criteria-registry__template-grid">{templateCards}</div>
        </section>
      ),
    });
  };
};

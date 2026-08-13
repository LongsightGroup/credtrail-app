import type { HtmlEscapedString } from "hono/utils/html";
import { appPage, type AppPage } from "../ui/render-page";

import type {
  LearnerRecordPresentationItem,
  LearnerRecordPresentationModel,
  LearnerRecordPresentationSection,
} from "../learner-record/learner-record-presentation";
import type { LearnerPathwayProgressRecord, LearnerPathwayRequirementState } from "@credtrail/db";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

interface CreateLearnerRecordPageInput {
  formatIsoTimestamp: (value: string) => string;
}

const countLabel = (count: number, noun: string): string => {
  return count === 1 ? `1 ${noun}` : `${count} ${noun}s`;
};

const shouldFormatAsTimestamp = (label: string): boolean => {
  return label === "Issued" || label === "Revised" || label === "Revoked";
};

const learnerRecordAppPage = (body: HonoElement): AppPage => {
  return appPage({
    title: "Learner record | CredTrail",
    body,
    assets: ["learnerRecordCss"],
  });
};

const pathwayRequirementLabel = (state: LearnerPathwayRequirementState): string => {
  switch (state) {
    case "met":
      return "Met";
    case "not_recorded":
      return "No evidence recorded yet";
    case "in_review":
      return "Needs review";
    case "waived":
      return "Waived";
    case "invalidated":
      return "Invalidated";
  }
};

const pathwayResultLabel = (pathway: LearnerPathwayProgressRecord): string => {
  if (
    pathway.evaluation.result === "needs_review" &&
    pathway.completionHandoff?.status === "eligible"
  ) {
    return "Approved for issuance";
  }

  if (
    pathway.evaluation.result === "needs_review" &&
    pathway.completionHandoff?.status === "issued"
  ) {
    return "Credential issued";
  }

  switch (pathway.evaluation.result) {
    case "complete":
      return "Complete";
    case "needs_review":
      return "Needs review";
    case "invalidated":
      return "Invalidated";
    case "in_progress":
      return "In progress";
  }
};

export const createLearnerRecordPage = (input: CreateLearnerRecordPageInput) => {
  const { formatIsoTimestamp } = input;

  const DetailRows = (props: {
    rows: readonly { label: string; value: string }[];
    emptyMessage: string;
  }): HonoElement => {
    if (props.rows.length === 0) {
      return <p class="learner-record__subtle">{props.emptyMessage}</p>;
    }

    return (
      <dl class="learner-record__detail-list">
        {props.rows.map((row) => {
          const value = shouldFormatAsTimestamp(row.label)
            ? `${formatIsoTimestamp(row.value)} UTC`
            : row.value;

          return (
            <div key={`${row.label}:${row.value}`} class="learner-record__detail-row">
              <dt>{row.label}</dt>
              <dd>{value}</dd>
            </div>
          );
        })}
      </dl>
    );
  };

  const EvidenceLinks = (props: { item: LearnerRecordPresentationItem }): HonoElement | null => {
    if (props.item.evidenceLinks.length === 0) {
      return null;
    }

    return (
      <div class="learner-record__meta-block">
        <h4>Evidence</h4>
        <ul class="learner-record__link-list">
          {props.item.evidenceLinks.map((href) => (
            <li key={href}>
              <a href={href} target="_blank" rel="noopener noreferrer">
                {href}
              </a>
            </li>
          ))}
        </ul>
      </div>
    );
  };

  const RecordItem = (props: { item: LearnerRecordPresentationItem }): HonoElement => {
    const item = props.item;

    return (
      <article class="learner-record__card">
        <div class="learner-record__card-topline">
          <p class="learner-record__card-kicker">{item.recordTypeLabel}</p>
          <div class="learner-record__pill-row">
            <span class="learner-record__pill learner-record__pill--trust">{item.trustLabel}</span>
            <span
              class={`learner-record__pill learner-record__pill--status learner-record__pill--status-${item.status}`}
            >
              {item.statusLabel}
            </span>
          </div>
        </div>
        <h3>{item.title}</h3>
        {item.description === null ? null : (
          <p class="learner-record__card-description">{item.description}</p>
        )}
        <p class="learner-record__provenance">{item.provenanceSummary}</p>
        <div class="learner-record__meta-grid">
          <section class="learner-record__meta-block">
            <h4>Record details</h4>
            <DetailRows
              rows={item.details}
              emptyMessage="No additional record details are attached to this item."
            />
          </section>
          <section class="learner-record__meta-block">
            <h4>Provenance</h4>
            <DetailRows
              rows={item.provenanceDetails}
              emptyMessage="No provenance details are available."
            />
          </section>
        </div>
        <EvidenceLinks item={item} />
        {item.publicBadgePath === null ? null : (
          <a class="learner-record__card-action" href={item.publicBadgePath}>
            Open public badge
          </a>
        )}
      </article>
    );
  };

  const RecordSection = (props: { section: LearnerRecordPresentationSection }): HonoElement => {
    return (
      <section class="learner-record__section" aria-labelledby={`section-${props.section.key}`}>
        <div class="learner-record__section-heading">
          <div>
            <p class="learner-record__section-kicker">{props.section.itemCountLabel}</p>
            <h2 id={`section-${props.section.key}`}>{props.section.title}</h2>
            <p>{props.section.description}</p>
          </div>
        </div>
        <div class="learner-record__card-grid">
          {props.section.items.map((item) => (
            <RecordItem key={item.id} item={item} />
          ))}
        </div>
      </section>
    );
  };

  return (
    tenantId: string,
    presentation: LearnerRecordPresentationModel,
    options: {
      switchOrganizationPath?: string | null;
      pathways?: readonly LearnerPathwayProgressRecord[];
    } = {},
  ): AppPage => {
    const learnerLabel = presentation.learnerDisplayName ?? "This learner";
    const dashboardPath = `/tenants/${encodeURIComponent(tenantId)}/learner/dashboard`;
    const heroLead =
      presentation.summary.total === 0
        ? "This unified record is ready for its first badge or learner-record entry."
        : `${countLabel(
            presentation.summary.issuerVerified,
            "institution-verified item",
          )} and ${countLabel(
            presentation.summary.supplemental,
            "learner-supplemental item",
          )} now live in one learner-facing record.`;
    const switchOrganizationPath = options.switchOrganizationPath?.trim();
    const pathways = options.pathways ?? [];

    return learnerRecordAppPage(
      <main class="learner-record">
        <section class="learner-record__hero">
          <div class="learner-record__hero-copy">
            <p class="learner-record__eyebrow">Unified learner record</p>
            <h1>{learnerLabel}</h1>
            <p class="learner-record__hero-lead">{heroLead}</p>
            <p class="learner-record__hero-note">
              Badges and non-badge achievements stay together here, with trust and history made
              explicit instead of hidden in separate tools.
            </p>
            <div class="learner-record__hero-actions">
              <a class="learner-record__hero-link" href={dashboardPath}>
                Return to learner dashboard
              </a>
              {switchOrganizationPath === undefined ||
              switchOrganizationPath.length === 0 ? null : (
                <a
                  class="learner-record__hero-link learner-record__hero-link--secondary"
                  href={switchOrganizationPath}
                >
                  Switch organization
                </a>
              )}
            </div>
          </div>
          <div class="learner-record__hero-metrics">
            <article class="learner-record__metric-card">
              <p class="learner-record__metric-label">Total record items</p>
              <p class="learner-record__metric-value">{String(presentation.summary.total)}</p>
              <p class="learner-record__metric-note">
                {countLabel(presentation.summary.badgeAssertions, "badge")} ·{" "}
                {countLabel(presentation.summary.recordEntries, "record entry")}
              </p>
            </article>
            <article class="learner-record__metric-card">
              <p class="learner-record__metric-label">Currently active</p>
              <p class="learner-record__metric-value">{String(presentation.summary.active)}</p>
              <p class="learner-record__metric-note">
                {String(presentation.summary.historical)} historical
              </p>
            </article>
          </div>
        </section>
        {pathways.length === 0 ? null : (
          <section
            class="learner-record__section learner-record__pathways"
            aria-labelledby="active-pathways-title"
          >
            <div class="learner-record__section-heading">
              <div>
                <p class="learner-record__section-kicker">Institution-defined programs</p>
                <h2 id="active-pathways-title">Active pathways</h2>
                <p>
                  Progress counts institution-verified evidence and approved exceptions only.
                  Learner-added items never satisfy an official requirement automatically.
                </p>
              </div>
            </div>
            <div class="learner-record__pathway-grid">
              {pathways.map((pathway) => (
                <article class="learner-record__pathway-card" key={pathway.enrollmentId}>
                  <div class="learner-record__card-topline">
                    <p class="learner-record__card-kicker">
                      {pathway.ownerOrgUnitName} · Version {String(pathway.versionNumber)}
                    </p>
                    <span
                      class={`learner-record__pill learner-record__pill--pathway-${pathway.evaluation.result}`}
                    >
                      {pathwayResultLabel(pathway)}
                    </span>
                  </div>
                  <h3>{pathway.pathwayTitle}</h3>
                  <p class="learner-record__card-description">{pathway.learnerDescription}</p>
                  <ol class="learner-record__pathway-requirements">
                    {pathway.evaluation.requirements.map((requirement) => (
                      <li
                        class={`learner-record__pathway-requirement learner-record__pathway-requirement--${requirement.state}`}
                        key={requirement.requirementId}
                      >
                        <div>
                          <strong>{requirement.title}</strong>
                          {requirement.description === null ? null : (
                            <p>{requirement.description}</p>
                          )}
                        </div>
                        <span>{pathwayRequirementLabel(requirement.state)}</span>
                        {requirement.evidenceIds.length === 0 ? null : (
                          <a href="#learner-record-items">
                            {countLabel(requirement.evidenceIds.length, "evidence record")}
                          </a>
                        )}
                      </li>
                    ))}
                  </ol>
                  {pathway.nextRequirement === null ? (
                    <p class="learner-record__pathway-next">
                      {pathway.completionHandoff?.status === "issued"
                        ? "Every requirement is satisfied and the final credential is issued."
                        : pathway.completionHandoff?.status === "eligible"
                          ? "Every requirement is satisfied and the issuance review is approved."
                          : pathway.evaluation.result === "needs_review"
                            ? "Next: an administrator reviews the final credential decision."
                            : "Every requirement is satisfied."}
                    </p>
                  ) : (
                    <p class="learner-record__pathway-next">
                      Next requirement: <strong>{pathway.nextRequirement.title}</strong>
                    </p>
                  )}
                  {pathway.completionHandoff?.status === "eligible" ? (
                    <p class="learner-record__pathway-next">
                      Your evidence is complete. The final credential is eligible for administrator
                      issuance; it has not been issued automatically.
                    </p>
                  ) : null}
                  {pathway.completionHandoff?.status === "issued" ? (
                    <p class="learner-record__pathway-next">
                      Your final credential has been issued.
                      {pathway.completionHandoff.assertionPublicId === null ? null : (
                        <>
                          {" "}
                          <a
                            href={`/badges/${encodeURIComponent(pathway.completionHandoff.assertionPublicId)}`}
                          >
                            View final credential
                          </a>
                        </>
                      )}
                    </p>
                  ) : null}
                  {pathway.completedAt === null ? null : (
                    <p class="learner-record__subtle">
                      Completion recorded {formatIsoTimestamp(pathway.completedAt)} UTC. Current
                      evidence is evaluated separately so later revocation does not erase this
                      history.
                    </p>
                  )}
                </article>
              ))}
            </div>
          </section>
        )}
        {presentation.sections.length > 0 ? null : (
          <section class="learner-record__empty-state">
            <h2>Nothing has been added yet</h2>
            <p>
              This learner account does not have any badge assertions or non-badge learner-record
              entries yet.
            </p>
          </section>
        )}
        <div id="learner-record-items">
          {presentation.sections.map((section) => (
            <RecordSection key={section.key} section={section} />
          ))}
        </div>
      </main>,
    );
  };
};

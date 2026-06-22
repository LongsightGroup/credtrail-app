import { appPage, type AppPage } from "../ui/render-page";
import {
  badgeTemplateCriteriaRegistryHref,
  badgeTemplateShowcaseHref,
  tenantBadgeCriteriaRegistryHref,
  tenantBadgeShowcaseHref,
} from "./badge-template-public-links";
import { buildSeoHeadContent, resolveAbsoluteWebUrl } from "./public-badge-renderer-helpers";
import type {
  CreatePublicBadgePageRenderersInput,
  PublicBadgePageRenderers,
  PublicBadgeWallEntryViewRecord,
} from "./public-badge-renderer-types";
import { BadgeWallButtonLink, BadgeWallCopyButton } from "./public-badge-ui";

export const createTenantBadgeWallPage = (
  input: CreatePublicBadgePageRenderersInput,
): PublicBadgePageRenderers["tenantBadgeWallPage"] => {
  const { formatIsoTimestamp, githubAvatarUrlForUsername, githubUsernameFromUrl, isWebUrl } = input;
  const toAbsoluteWebUrl = (requestUrl: string, value: string | null): string | null => {
    return resolveAbsoluteWebUrl({ requestUrl, value, isWebUrl });
  };

  return (
    requestUrl: string,
    tenantId: string,
    entries: readonly PublicBadgeWallEntryViewRecord[],
    filterBadgeTemplateId: string | null,
  ): AppPage => {
    const displayTenantName = tenantId;
    const firstBadgeTitle = entries.length > 0 ? (entries[0]?.badgeTitle ?? null) : null;
    const filterLabel = firstBadgeTitle ?? filterBadgeTemplateId;
    const heroEntry = filterBadgeTemplateId === null ? null : (entries[0] ?? null);
    const heroBadgeInitial = (filterLabel ?? "Badge").trim().slice(0, 1).toUpperCase() || "B";
    const title =
      filterBadgeTemplateId === null
        ? `Issued Credentials · ${displayTenantName}`
        : `${filterLabel ?? "Credentials"} · ${displayTenantName}`;
    const badgeWallPath =
      filterBadgeTemplateId === null
        ? tenantBadgeShowcaseHref(tenantId)
        : badgeTemplateShowcaseHref(tenantId, filterBadgeTemplateId);
    const canonicalUrl = new URL(badgeWallPath, requestUrl).toString();
    const subtitle =
      filterBadgeTemplateId === null
        ? `Publicly verified credentials issued by this institution.`
        : `Publicly verified credentials for ${filterLabel ?? "this badge"}.`;
    const criteriaRegistryPath =
      filterBadgeTemplateId === null
        ? tenantBadgeCriteriaRegistryHref(tenantId)
        : badgeTemplateCriteriaRegistryHref(tenantId, filterBadgeTemplateId);
    const pageTitle = `${title} | CredTrail`;
    const socialImageUrl =
      entries
        .map((entry) => toAbsoluteWebUrl(requestUrl, entry.badgeImageUri))
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
      assets: ["publicBadgeCss", "publicBadgeJs"],
      variant: "open",
      body: (
        <section class="badge-wall">
          <header class="badge-wall__hero">
            {heroEntry === null ? null : (
              <div class="badge-wall__hero-image-frame">
                {heroEntry.badgeImageUri === null ? (
                  <span class="badge-wall__hero-image badge-wall__hero-image--placeholder">
                    {heroBadgeInitial}
                  </span>
                ) : (
                  <img
                    class="badge-wall__hero-image"
                    src={heroEntry.badgeImageUri}
                    alt={`${heroEntry.badgeTitle} badge artwork`}
                  />
                )}
              </div>
            )}
            <div class="badge-wall__hero-copy">
              <h1>{title}</h1>
              <p class="badge-wall__lead">{subtitle}</p>
              {heroEntry?.badgeDescription === null ||
              heroEntry?.badgeDescription === undefined ? null : (
                <p class="badge-wall__description">{heroEntry.badgeDescription}</p>
              )}
              <div class="badge-wall__hero-actions">
                <p class="badge-wall__count">{String(entries.length)} issued badges</p>
                <a class="badge-wall__hero-link" href={criteriaRegistryPath}>
                  View criteria registry
                </a>
              </div>
            </div>
          </header>
          {entries.length === 0 ? (
            <p class="badge-wall__empty">No public badges found for this showcase.</p>
          ) : (
            <ol class="badge-wall__list">
              {entries.map((entry) => {
                const username = githubUsernameFromUrl(entry.recipientIdentity);
                const recipientLabel = username === null ? entry.recipientIdentity : `@${username}`;
                const avatarUrl = username === null ? null : githubAvatarUrlForUsername(username);
                const badgePath = `/badges/${encodeURIComponent(entry.assertionPublicId)}`;
                const badgeUrl = new URL(badgePath, requestUrl).toString();
                const issuedAt = `${formatIsoTimestamp(entry.issuedAt)} UTC`;
                const lifecycleState = entry.lifecycle.state;
                const statusLabel =
                  lifecycleState === "active"
                    ? "Verified"
                    : lifecycleState.slice(0, 1).toUpperCase() + lifecycleState.slice(1);
                const statusClass = lifecycleState === "active" ? "verified" : lifecycleState;
                const transitionedAt =
                  lifecycleState === "revoked"
                    ? (entry.lifecycle.revokedAt ?? entry.lifecycle.transitionedAt)
                    : entry.lifecycle.transitionedAt;
                const reasonText = entry.lifecycle.reason ?? entry.lifecycle.reasonCode;
                const badgeInitial = entry.badgeTitle.trim().slice(0, 1).toUpperCase() || "B";

                return (
                  <li class="badge-wall__item" key={entry.assertionPublicId}>
                    <div class="badge-wall__summary">
                      <div class="badge-wall__identity">
                        {entry.badgeImageUri === null ? (
                          <span
                            class="badge-wall__badge-image badge-wall__badge-image--placeholder"
                            aria-hidden="true"
                          >
                            {badgeInitial}
                          </span>
                        ) : (
                          <img
                            class="badge-wall__badge-image"
                            src={entry.badgeImageUri}
                            alt={entry.badgeTitle}
                            loading="lazy"
                          />
                        )}
                        <div class="badge-wall__stack">
                          <div class="badge-wall__recipient">
                            {avatarUrl === null ? null : (
                              <img
                                class="badge-wall__avatar"
                                src={avatarUrl}
                                alt={`${recipientLabel} GitHub avatar`}
                                loading="lazy"
                              />
                            )}
                            <p class="badge-wall__name">{recipientLabel}</p>
                          </div>
                          <p class="badge-wall__badge-title">{entry.badgeTitle}</p>
                          <p class={`badge-wall__meta badge-wall__meta--${statusClass}`}>
                            {statusLabel} · Issued {issuedAt}
                          </p>
                          {transitionedAt === null || lifecycleState === "active" ? null : (
                            <p class={`badge-wall__meta badge-wall__meta--${statusClass}`}>
                              {statusLabel} {formatIsoTimestamp(transitionedAt)} UTC
                            </p>
                          )}
                          {reasonText === null || lifecycleState === "active" ? null : (
                            <p class="badge-wall__meta badge-wall__meta--reason">{reasonText}</p>
                          )}
                        </div>
                      </div>
                      <div class="badge-wall__actions">
                        <BadgeWallButtonLink href={badgePath} variant="primary">
                          View credential
                        </BadgeWallButtonLink>
                        <BadgeWallCopyButton value={badgeUrl} />
                        <p class="badge-wall__copy-status" aria-live="polite"></p>
                      </div>
                    </div>
                  </li>
                );
              })}
            </ol>
          )}
        </section>
      ),
    });
  };
};

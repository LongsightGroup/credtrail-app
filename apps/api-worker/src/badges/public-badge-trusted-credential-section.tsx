import type { HtmlEscapedString } from "hono/utils/html";
import type { TrustEdCredentialDetails } from "./public-badge-helpers";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

const hasTrustEdCredentialDetails = (details: TrustEdCredentialDetails): boolean => {
  return (
    details.achievementType !== null ||
    details.criteriaNarrative !== null ||
    details.alignments.length > 0 ||
    details.skills.length > 0 ||
    details.issuerAuthority !== null ||
    details.assessments.length > 0 ||
    details.results.length > 0 ||
    details.rubrics.length > 0 ||
    details.duration !== null ||
    details.credits !== null ||
    details.endorsements.length > 0
  );
};

export const PublicBadgeTrustEdCredentialSection = ({
  details,
}: {
  details: TrustEdCredentialDetails;
}): HonoElement | null => {
  if (!hasTrustEdCredentialDetails(details)) {
    return null;
  }

  return (
    <section class="public-badge__card public-badge__stack-sm">
      <div class="public-badge__section-heading-row">
        <h2 class="public-badge__section-title">Trust metadata</h2>
        <span class="public-badge__metadata-badge">TrustEd-aligned</span>
      </div>
      <p class="public-badge__achievement-copy">
        Structured credential data published inside this Open Badges 3.0 record.
      </p>
      <dl class="public-badge__trust-grid">
        {details.achievementType === null ? null : (
          <>
            <dt>Achievement type</dt>
            <dd>{details.achievementType}</dd>
          </>
        )}
        {details.criteriaNarrative === null ? null : (
          <>
            <dt>Criteria</dt>
            <dd>
              {details.criteriaNarrative}
              {details.criteriaUri === null ? null : (
                <>
                  {" "}
                  <a href={details.criteriaUri} target="_blank" rel="noopener noreferrer">
                    View criteria
                  </a>
                </>
              )}
            </dd>
          </>
        )}
        {details.results.length === 0 ? null : (
          <>
            <dt>Results</dt>
            <dd>
              <ul class="public-badge__trust-list">
                {details.results.map((result) => (
                  <li key={`${result.value}:${result.resultDate}`}>
                    {result.value} on {result.resultDate}
                  </li>
                ))}
              </ul>
            </dd>
          </>
        )}
        {details.skills.length === 0 ? null : (
          <>
            <dt>Skills</dt>
            <dd>
              <ul class="public-badge__trust-list">
                {details.skills.map((skill) => {
                  const label = skill.name ?? skill.identifierUri ?? "Represented skill";

                  return (
                    <li key={`${label}:${skill.identifierUri ?? ""}`}>
                      {skill.identifierUri === null ? (
                        <span>{label}</span>
                      ) : (
                        <a href={skill.identifierUri} target="_blank" rel="noopener noreferrer">
                          {label}
                        </a>
                      )}
                      {skill.source === null ? null : (
                        <span class="public-badge__trust-muted"> ({skill.source})</span>
                      )}
                    </li>
                  );
                })}
              </ul>
            </dd>
          </>
        )}
        {details.issuerAuthority === null ? null : (
          <>
            <dt>Issuer authority</dt>
            <dd>
              {details.issuerAuthority.uri === null ? (
                <span>{details.issuerAuthority.name ?? "Authority listed"}</span>
              ) : (
                <a href={details.issuerAuthority.uri} target="_blank" rel="noopener noreferrer">
                  {details.issuerAuthority.name ?? details.issuerAuthority.uri}
                </a>
              )}
              {details.issuerAuthority.authorityType === null ? null : (
                <span class="public-badge__trust-muted">
                  {" "}
                  ({details.issuerAuthority.authorityType})
                </span>
              )}
            </dd>
          </>
        )}
        {details.assessments.length === 0 ? null : (
          <>
            <dt>Assessment</dt>
            <dd>
              <ul class="public-badge__trust-list">
                {details.assessments.map((assessment) => (
                  <li key={`${assessment.description ?? ""}:${assessment.assessmentDate ?? ""}`}>
                    {assessment.description ?? "Assessment"}
                    {assessment.assessmentDate === null ? null : (
                      <span class="public-badge__trust-muted"> ({assessment.assessmentDate})</span>
                    )}
                  </li>
                ))}
              </ul>
            </dd>
          </>
        )}
        {details.alignments.length === 0 ? null : (
          <>
            <dt>Framework alignment</dt>
            <dd>
              <ul class="public-badge__trust-list">
                {details.alignments.map((alignment) => {
                  const label = alignment.targetName ?? alignment.targetUrl;
                  const framework =
                    alignment.targetFramework === null ? null : (
                      <span class="public-badge__trust-muted"> ({alignment.targetFramework})</span>
                    );

                  return (
                    <li key={alignment.targetUrl}>
                      <a href={alignment.targetUrl} target="_blank" rel="noopener noreferrer">
                        {label}
                      </a>
                      {framework}
                    </li>
                  );
                })}
              </ul>
            </dd>
          </>
        )}
        {details.rubrics.length === 0 ? null : (
          <>
            <dt>Rubric</dt>
            <dd>
              <ul class="public-badge__trust-list">
                {details.rubrics.map((rubric) => {
                  const label = rubric.name ?? rubric.uri ?? "Rubric";

                  return (
                    <li key={`${label}:${rubric.uri ?? ""}`}>
                      {rubric.uri === null ? (
                        <span>{label}</span>
                      ) : (
                        <a href={rubric.uri} target="_blank" rel="noopener noreferrer">
                          {label}
                        </a>
                      )}
                    </li>
                  );
                })}
              </ul>
            </dd>
          </>
        )}
        {details.duration === null ? null : (
          <>
            <dt>Duration</dt>
            <dd>{details.duration}</dd>
          </>
        )}
        {details.credits === null ? null : (
          <>
            <dt>Credits</dt>
            <dd>
              {[
                details.credits.available === null
                  ? null
                  : `Available: ${details.credits.available}`,
                details.credits.earned === null ? null : `Earned: ${details.credits.earned}`,
              ]
                .filter((entry): entry is string => entry !== null)
                .join("; ")}
            </dd>
          </>
        )}
        {details.endorsements.length === 0 ? null : (
          <>
            <dt>Endorsement</dt>
            <dd>
              <ul class="public-badge__trust-list">
                {details.endorsements.map((endorsement) => {
                  const label =
                    endorsement.endorserName ?? endorsement.endorserUri ?? "Endorsement";

                  return (
                    <li key={`${label}:${endorsement.endorserUri ?? ""}`}>
                      {endorsement.endorserUri === null ? (
                        <span>{label}</span>
                      ) : (
                        <a href={endorsement.endorserUri} target="_blank" rel="noopener noreferrer">
                          {label}
                        </a>
                      )}
                    </li>
                  );
                })}
              </ul>
            </dd>
          </>
        )}
      </dl>
    </section>
  );
};

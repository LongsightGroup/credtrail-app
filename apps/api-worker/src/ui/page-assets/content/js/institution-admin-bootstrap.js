const parsedContext = readAdminContext();

if (!parsedContext) {
  return;
}

const badgeRuleApiPath =
  parsedContext && typeof parsedContext.badgeRuleApiPath === "string"
    ? parsedContext.badgeRuleApiPath
    : "";
const reportingFiltersForm = document.getElementById("reporting-filters-form");
const reportingFiltersStatus = document.getElementById("reporting-filters-status");
const ruleGovernanceForm = document.getElementById("rule-governance-form");
const ruleGovernanceStatus = document.getElementById("rule-governance-status");
const ruleGovernanceOutput = document.getElementById("rule-governance-output");

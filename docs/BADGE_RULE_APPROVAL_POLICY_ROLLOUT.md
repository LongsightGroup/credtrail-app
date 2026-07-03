# Badge Rule Approval Policy Rollout

Migration `0050_badge_rule_approval_policies.sql` moves badge rule approval governance from rule-authored chains to tenant and org-unit policy.
Migration `0051_badge_rule_approval_separation_of_duties.sql` adds submitter tracking, named approver targets, approver groups, request-changes decisions, and explicit self-certification policy.

Operational behavior:

- New submissions materialize approval steps from the resolved badge rule approval policy.
- Tenant default policy rows are seeded during migration and on tenant creation.
- The v1 governance UI edits the tenant-default policy only and offers one reviewer role step.
- Org-unit overrides and multi-step policy chains are DB-supported but remain internal until an operator-facing workflow is added.
- Existing `pending_approval` rule versions keep their already-materialized approval steps.
- Policy changes do not rewrite in-flight approval chains. Finish, reject, or supersede those versions with a new draft submission when they need current policy.
- Rule approval scope is a snapshot captured from the selected badge template owner org unit at rule create or draft edit time.
- Rule version creators and submitters cannot decide approval steps on that version.
- Automatic approval requires `allow_self_certification`; the v1 governance UI sets it only when an admin explicitly chooses automatic approval.
- Approval steps can target a role threshold, a specific user, or an approver group. The v1 governance UI still edits only the tenant-default role threshold step.
- Use `createBadgeRuleApproverGroup` and `addBadgeRuleApproverGroupMember` in `@credtrail/db` to manage approver groups until admin UI ships.
- `changes_requested` returns the version to draft with reviewer comments. Resubmission rematerializes the approval chain from current policy.

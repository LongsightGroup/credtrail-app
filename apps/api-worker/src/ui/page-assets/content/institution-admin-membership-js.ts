export const INSTITUTION_ADMIN_MEMBERSHIP_JS = `
  if (tenantMemberForm instanceof HTMLFormElement && tenantMemberStatus instanceof HTMLElement) {
    tenantMemberForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setStatus(tenantMemberStatus, 'Adding member...', false);

      const data = new FormData(tenantMemberForm);
      const emailRaw = data.get('email');
      const roleRaw = data.get('role');
      const email = typeof emailRaw === 'string' ? emailRaw.trim() : '';
      const role = typeof roleRaw === 'string' ? roleRaw.trim() : '';
      const validRoles = new Set(['owner', 'admin', 'issuer', 'viewer']);

      if (email.length === 0 || role.length === 0) {
        setStatus(tenantMemberStatus, 'Email and tenant role are required.', true);
        return;
      }

      if (!validRoles.has(role)) {
        setStatus(tenantMemberStatus, 'Invalid tenant role.', true);
        return;
      }

      try {
        const response = await fetch(tenantMembersApiPath, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            email,
            role,
            sendInvite: data.get('sendInvite') !== null,
          }),
        });
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(tenantMemberStatus, errorDetailFromPayload(payload), true);
          return;
        }

        setStatus(tenantMemberStatus, 'Member saved.', false, 'success');
        setTimeout(() => {
          reloadCurrentPage();
        }, 700);
      } catch {
        setStatus(tenantMemberStatus, 'Unable to add the member from this browser session.', true);
      }
    });
  }

  if (tenantMemberBody instanceof HTMLElement && tenantMemberListStatus instanceof HTMLElement) {
    tenantMemberBody.addEventListener('change', async (event) => {
      const target = event.target;

      if (!(target instanceof HTMLSelectElement)) {
        return;
      }

      const userId = target.dataset.tenantMemberRoleUserId ?? '';
      const currentRole = target.dataset.tenantMemberCurrentRole ?? '';
      const nextRole = target.value.trim();
      const validRoles = new Set(['owner', 'admin', 'issuer', 'viewer']);

      if (userId.length === 0) {
        setStatus(tenantMemberListStatus, 'Member user ID is missing from this role control.', true);
        target.value = currentRole;
        return;
      }

      if (nextRole === currentRole) {
        return;
      }

      if (!validRoles.has(nextRole)) {
        setStatus(tenantMemberListStatus, 'Invalid tenant role.', true);
        target.value = currentRole;
        return;
      }

      setStatus(tenantMemberListStatus, 'Updating member role...', false);
      target.disabled = true;

      try {
        const response = await fetch(
          tenantMembersApiPath + '/' + encodeURIComponent(userId) + '/role',
          {
            method: 'PATCH',
            headers: {
              'content-type': 'application/json',
            },
            body: JSON.stringify({
              role: nextRole,
            }),
          },
        );
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(tenantMemberListStatus, errorDetailFromPayload(payload), true);
          target.value = currentRole;
          target.disabled = false;
          return;
        }

        setStatus(tenantMemberListStatus, 'Member role updated.', false, 'success');
        setTimeout(() => {
          reloadCurrentPage();
        }, 700);
      } catch {
        setStatus(
          tenantMemberListStatus,
          'Unable to update the member role from this browser session.',
          true,
        );
        target.value = currentRole;
        target.disabled = false;
      }
    });

    tenantMemberBody.addEventListener('click', async (event) => {
      const target = event.target;

      if (!(target instanceof HTMLElement)) {
        return;
      }

      const inviteButton = target.closest('[data-tenant-member-invite-user-id]');

      if (inviteButton instanceof HTMLElement) {
        const userId = inviteButton.dataset.tenantMemberInviteUserId ?? '';
        const email = inviteButton.dataset.tenantMemberEmail ?? 'this member';

        if (userId.length === 0) {
          setStatus(tenantMemberListStatus, 'Member user ID is missing from invite action.', true);
          return;
        }

        setStatus(tenantMemberListStatus, 'Sending member invite...', false);

        try {
          const response = await fetch(
            tenantMembersApiPath + '/' + encodeURIComponent(userId) + '/invite',
            {
              method: 'POST',
            },
          );
          const payload = await parseJsonBody(response);

          if (!response.ok) {
            setStatus(tenantMemberListStatus, errorDetailFromPayload(payload), true);
            return;
          }

          const deliveryStatus =
            payload &&
            payload.invite &&
            typeof payload.invite.deliveryStatus === 'string'
              ? payload.invite.deliveryStatus
              : 'sent';
          setStatus(
            tenantMemberListStatus,
            'Invite processed for ' + email + ' (' + deliveryStatus + ').',
            false,
            deliveryStatus === 'failed' ? 'warning' : 'success',
          );
        } catch {
          setStatus(
            tenantMemberListStatus,
            'Unable to send the member invite from this browser session.',
            true,
          );
        }

        return;
      }

      const removeButton = target.closest('[data-tenant-member-remove-user-id]');

      if (!(removeButton instanceof HTMLElement)) {
        return;
      }

      const userId = removeButton.dataset.tenantMemberRemoveUserId ?? '';
      const email = removeButton.dataset.tenantMemberEmail ?? 'this member';

      if (userId.length === 0) {
        setStatus(tenantMemberListStatus, 'Member user ID is missing from remove action.', true);
        return;
      }

      if (!window.confirm('Remove tenant access for ' + email + '?')) {
        return;
      }

      setStatus(tenantMemberListStatus, 'Removing tenant member...', false);

      try {
        const response = await fetch(
          tenantMembersApiPath + '/' + encodeURIComponent(userId),
          {
            method: 'DELETE',
          },
        );
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(tenantMemberListStatus, errorDetailFromPayload(payload), true);
          return;
        }

        const removed = payload && typeof payload.removed === 'boolean' ? payload.removed : false;

        if (!removed) {
          setStatus(tenantMemberListStatus, 'No matching tenant membership was found.', true);
          return;
        }

        setStatus(tenantMemberListStatus, 'Tenant member removed.', false, 'success');
        setTimeout(() => {
          reloadCurrentPage();
        }, 700);
      } catch {
        setStatus(
          tenantMemberListStatus,
          'Unable to remove the tenant member from this browser session.',
          true,
        );
      }
    });
  }

  if (membershipScopeForm instanceof HTMLFormElement && membershipScopeStatus instanceof HTMLElement) {
    membershipScopeForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setStatus(membershipScopeStatus, 'Saving scoped role...', false);
      const data = new FormData(membershipScopeForm);
      const userIdRaw = data.get('userId');
      const orgUnitIdRaw = data.get('orgUnitId');
      const roleRaw = data.get('role');
      const userId = typeof userIdRaw === 'string' ? userIdRaw.trim() : '';
      const orgUnitId = typeof orgUnitIdRaw === 'string' ? orgUnitIdRaw.trim() : '';
      const role = typeof roleRaw === 'string' ? roleRaw.trim() : '';

      if (userId.length === 0 || orgUnitId.length === 0 || role.length === 0) {
        setStatus(
          membershipScopeStatus,
          'Tenant member, org unit, and scoped role are required.',
          true,
        );
        return;
      }

      const validRoles = new Set(['admin', 'issuer', 'viewer']);

      if (!validRoles.has(role)) {
        setStatus(membershipScopeStatus, 'Invalid role. Use admin, issuer, or viewer.', true);
        return;
      }

      try {
        const response = await fetch(
          tenantUsersApiPathPrefix +
            '/' +
            encodeURIComponent(userId) +
            '/org-unit-scopes/' +
            encodeURIComponent(orgUnitId),
          {
            method: 'PUT',
            headers: {
              'content-type': 'application/json',
            },
            body: JSON.stringify({
              role,
            }),
          },
        );
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(membershipScopeStatus, errorDetailFromPayload(payload), true);
          return;
        }

        setStatus(membershipScopeStatus, 'Scoped role saved for ' + userId + '.', false, 'success');
        setTimeout(() => {
          reloadCurrentPage();
        }, 700);
      } catch {
        setStatus(
          membershipScopeStatus,
          'Unable to save the scoped role from this browser session.',
          true,
        );
      }
    });
  }

  if (membershipScopeBody instanceof HTMLElement && membershipScopeListStatus instanceof HTMLElement) {
    membershipScopeBody.addEventListener('click', async (event) => {
      const target = event.target;

      if (!(target instanceof HTMLElement)) {
        return;
      }

      const removeButton = target.closest('[data-membership-scope-remove-user-id]');

      if (!(removeButton instanceof HTMLElement)) {
        return;
      }

      const userId = removeButton.dataset.membershipScopeRemoveUserId ?? '';
      const orgUnitId = removeButton.dataset.membershipScopeRemoveOrgUnitId ?? '';
      const label = removeButton.dataset.membershipScopeRemoveLabel ?? 'this scoped role';

      if (userId.length === 0 || orgUnitId.length === 0) {
        setStatus(membershipScopeListStatus, 'Scoped role identifiers are missing.', true);
        return;
      }

      if (!window.confirm('Remove scoped role for ' + label + '?')) {
        return;
      }

      setStatus(membershipScopeListStatus, 'Removing scoped role...', false);

      try {
        const response = await fetch(
          tenantUsersApiPathPrefix +
            '/' +
            encodeURIComponent(userId) +
            '/org-unit-scopes/' +
            encodeURIComponent(orgUnitId),
          {
            method: 'DELETE',
          },
        );
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(membershipScopeListStatus, errorDetailFromPayload(payload), true);
          return;
        }

        const removed = payload && typeof payload.removed === 'boolean' ? payload.removed : false;

        if (!removed) {
          setStatus(membershipScopeListStatus, 'No matching scoped role was found.', true);
          return;
        }

        setStatus(membershipScopeListStatus, 'Scoped role removed.', false, 'success');
        setTimeout(() => {
          reloadCurrentPage();
        }, 700);
      } catch {
        setStatus(
          membershipScopeListStatus,
          'Unable to remove the scoped role from this browser session.',
          true,
        );
      }
    });
  }

  if (delegatedGrantForm instanceof HTMLFormElement && delegatedGrantStatus instanceof HTMLElement) {
    delegatedGrantForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setStatus(delegatedGrantStatus, 'Saving delegation...', false);
      const data = new FormData(delegatedGrantForm);
      const delegateUserIdRaw = data.get('delegateUserId');
      const orgUnitIdRaw = data.get('orgUnitId');
      const badgeTemplateIdsRaw = data.get('badgeTemplateIds');
      const reasonRaw = data.get('reason');
      const endsAtRaw = data.get('endsAt');
      const delegateUserId = typeof delegateUserIdRaw === 'string' ? delegateUserIdRaw.trim() : '';
      const orgUnitId = typeof orgUnitIdRaw === 'string' ? orgUnitIdRaw.trim() : '';
      const badgeTemplateIds = toCommaSeparatedList(badgeTemplateIdsRaw);
      const reason = typeof reasonRaw === 'string' ? reasonRaw.trim() : '';
      const endsAtLocal = typeof endsAtRaw === 'string' ? endsAtRaw.trim() : '';
      const allowedActions = data
        .getAll('allowedAction')
        .map((value) => (typeof value === 'string' ? value.trim() : ''))
        .filter((value) => value.length > 0);

      if (delegateUserId.length === 0 || orgUnitId.length === 0) {
        setStatus(delegatedGrantStatus, 'Delegate and org unit are required.', true);
        return;
      }

      if (allowedActions.length === 0) {
        setStatus(delegatedGrantStatus, 'Select at least one allowed action.', true);
        return;
      }

      const validActions = new Set(['issue_badge', 'revoke_badge', 'manage_lifecycle']);
      const invalidAction = allowedActions.find((action) => !validActions.has(action));

      if (invalidAction !== undefined) {
        setStatus(
          delegatedGrantStatus,
          'Invalid delegated action: ' + invalidAction + '.',
          true,
        );
        return;
      }

      if (endsAtLocal.length === 0) {
        setStatus(delegatedGrantStatus, 'Choose when this delegation should end.', true);
        return;
      }

      const parsedEndsAtMs = Date.parse(endsAtLocal);

      if (!Number.isFinite(parsedEndsAtMs)) {
        setStatus(delegatedGrantStatus, 'Ends at must be a valid date/time.', true);
        return;
      }

      const endsAtIso = new Date(parsedEndsAtMs).toISOString();

      try {
        const response = await fetch(
          tenantUsersApiPathPrefix +
            '/' +
            encodeURIComponent(delegateUserId) +
            '/issuing-authority-grants',
          {
            method: 'POST',
            headers: {
              'content-type': 'application/json',
            },
            body: JSON.stringify({
              orgUnitId,
              allowedActions,
              ...(badgeTemplateIds.length > 0 ? { badgeTemplateIds } : {}),
              endsAt: endsAtIso,
              ...(reason.length > 0 ? { reason } : {}),
            }),
          },
        );
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(delegatedGrantStatus, errorDetailFromPayload(payload), true);
          return;
        }

        const grantId =
          payload && payload.grant && typeof payload.grant.id === 'string'
            ? payload.grant.id
            : '';
        setStatus(
          delegatedGrantStatus,
          'Delegation saved.' + (grantId.length > 0 ? ' Grant ID: ' + grantId + '.' : ''),
          false,
          'success',
        );
        setTimeout(() => {
          reloadCurrentPage();
        }, 700);
      } catch {
        setStatus(
          delegatedGrantStatus,
          'Unable to save the delegation from this browser session.',
          true,
        );
      }
    });
  }

  if (delegatedGrantBody instanceof HTMLElement && delegatedGrantListStatus instanceof HTMLElement) {
    delegatedGrantBody.addEventListener('click', async (event) => {
      const target = event.target;

      if (!(target instanceof HTMLElement)) {
        return;
      }

      const removeButton = target.closest('[data-delegated-grant-remove-id]');

      if (!(removeButton instanceof HTMLElement)) {
        return;
      }

      const delegateUserId = removeButton.dataset.delegatedGrantRemoveUserId ?? '';
      const grantId = removeButton.dataset.delegatedGrantRemoveId ?? '';
      const label = removeButton.dataset.delegatedGrantRemoveLabel ?? 'this delegation';

      if (delegateUserId.length === 0 || grantId.length === 0) {
        setStatus(delegatedGrantListStatus, 'Delegation identifiers are missing.', true);
        return;
      }

      if (!window.confirm('Remove delegation for ' + label + '?')) {
        return;
      }

      setStatus(delegatedGrantListStatus, 'Removing delegation...', false);

      try {
        const response = await fetch(
          tenantUsersApiPathPrefix +
            '/' +
            encodeURIComponent(delegateUserId) +
            '/issuing-authority-grants/' +
            encodeURIComponent(grantId) +
            '/revoke',
          {
            method: 'POST',
            headers: {
              'content-type': 'application/json',
            },
            body: JSON.stringify({}),
          },
        );
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(delegatedGrantListStatus, errorDetailFromPayload(payload), true);
          return;
        }

        setStatus(delegatedGrantListStatus, 'Delegation removed.', false, 'success');
        setTimeout(() => {
          reloadCurrentPage();
        }, 700);
      } catch {
        setStatus(
          delegatedGrantListStatus,
          'Unable to remove the delegation from this browser session.',
          true,
        );
      }
    });
  }
`;

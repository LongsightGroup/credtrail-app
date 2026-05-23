export const INSTITUTION_ADMIN_ISSUE_AUTH_JS = `
  if (manualIssueForm instanceof HTMLFormElement && manualIssueStatus instanceof HTMLElement) {
    manualIssueForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setStatus(manualIssueStatus, 'Issuing badge...', false);
      const data = new FormData(manualIssueForm);
      const recipientIdentityRaw = data.get('recipientIdentity');
      const badgeTemplateIdRaw = data.get('badgeTemplateId');
      const recipientIdentity =
        typeof recipientIdentityRaw === 'string' ? recipientIdentityRaw.trim().toLowerCase() : '';
      const badgeTemplateId =
        typeof badgeTemplateIdRaw === 'string' ? badgeTemplateIdRaw.trim() : '';

      if (recipientIdentity.length === 0 || badgeTemplateId.length === 0) {
        setStatus(manualIssueStatus, 'Recipient email and badge template are required.', true);
        return;
      }

      try {
        const response = await fetch(manualIssueApiPath, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            badgeTemplateId,
            recipientIdentity,
            recipientIdentityType: 'email',
            recipientIdentifiers: [
              {
                identifierType: 'emailAddress',
                identifier: recipientIdentity,
              },
            ],
          }),
        });

        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(manualIssueStatus, errorDetailFromPayload(payload), true);
          return;
        }

        const assertionId =
          payload && typeof payload.assertionId === 'string' ? payload.assertionId : null;
        const link =
          assertionId === null
            ? ''
            : ' Open /badges/' + assertionId + ' (redirects to canonical URL).';
        setStatus(manualIssueStatus, 'Badge issued for ' + recipientIdentity + '.' + link, false);
      } catch {
        setStatus(manualIssueStatus, 'Unable to issue badge from this browser session.', true);
      }
    });
  }

  if (
    enterpriseAuthPolicyForm instanceof HTMLFormElement &&
    enterpriseAuthPolicyStatus instanceof HTMLElement &&
    authPolicyApiPath.length > 0
  ) {
    enterpriseAuthPolicyForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setStatus(enterpriseAuthPolicyStatus, 'Saving auth policy...', false);

      const data = new FormData(enterpriseAuthPolicyForm);
      const loginModeRaw = data.get('loginMode');
      const defaultProviderIdRaw = data.get('defaultProviderId');
      const loginMode = typeof loginModeRaw === 'string' ? loginModeRaw.trim() : '';
      const defaultProviderId =
        typeof defaultProviderIdRaw === 'string' ? defaultProviderIdRaw.trim() : '';

      if (loginMode.length === 0) {
        setStatus(enterpriseAuthPolicyStatus, 'Login mode is required.', true);
        return;
      }

      try {
        const response = await fetch(authPolicyApiPath, {
          method: 'PUT',
          headers: {
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            loginMode,
            breakGlassEnabled: data.get('breakGlassEnabled') !== null,
            localMfaRequired: data.get('localMfaRequired') !== null,
            defaultProviderId: defaultProviderId.length > 0 ? defaultProviderId : null,
          }),
        });
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(enterpriseAuthPolicyStatus, errorDetailFromPayload(payload), true);
          return;
        }

        setStatus(enterpriseAuthPolicyStatus, 'Enterprise auth policy saved.', false);
        setTimeout(() => {
          window.location.assign(tenantAdminPath);
        }, 900);
      } catch {
        setStatus(enterpriseAuthPolicyStatus, 'Unable to save enterprise auth policy.', true);
      }
    });
  }

  if (
    enterpriseAuthProviderForm instanceof HTMLFormElement &&
    enterpriseAuthProviderStatus instanceof HTMLElement &&
    authProvidersApiPath.length > 0
  ) {
    enterpriseAuthProviderForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setStatus(enterpriseAuthProviderStatus, 'Saving auth provider...', false);

      const data = new FormData(enterpriseAuthProviderForm);
      const providerIdRaw = data.get('providerId');
      const protocolRaw = data.get('protocol');
      const labelRaw = data.get('label');
      const configJsonRaw = data.get('configJson');
      const providerId = typeof providerIdRaw === 'string' ? providerIdRaw.trim() : '';
      const protocol = typeof protocolRaw === 'string' ? protocolRaw.trim() : '';
      const label = typeof labelRaw === 'string' ? labelRaw.trim() : '';
      const configJson = typeof configJsonRaw === 'string' ? configJsonRaw.trim() : '';

      if (protocol.length === 0 || label.length === 0 || configJson.length === 0) {
        setStatus(enterpriseAuthProviderStatus, 'Protocol, label, and config JSON are required.', true);
        return;
      }

      const method = providerId.length > 0 ? 'PUT' : 'POST';
      const requestPath =
        method === 'PUT'
          ? authProvidersApiPath + '/' + encodeURIComponent(providerId)
          : authProvidersApiPath;

      try {
        const response = await fetch(requestPath, {
          method,
          headers: {
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            protocol,
            label,
            enabled: data.get('enabled') !== null,
            isDefault: data.get('isDefault') !== null,
            configJson,
          }),
        });
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(enterpriseAuthProviderStatus, errorDetailFromPayload(payload), true);
          return;
        }

        setStatus(
          enterpriseAuthProviderStatus,
          providerId.length > 0 ? 'Enterprise auth provider updated.' : 'Enterprise auth provider created.',
          false,
        );
        setTimeout(() => {
          window.location.assign(tenantAdminPath);
        }, 900);
      } catch {
        setStatus(enterpriseAuthProviderStatus, 'Unable to save enterprise auth provider.', true);
      }
    });
  }

  if (
    enterpriseAuthProviderResetButton instanceof HTMLButtonElement &&
    enterpriseAuthProviderForm instanceof HTMLFormElement
  ) {
    enterpriseAuthProviderResetButton.addEventListener('click', () => {
      resetEnterpriseAuthProviderForm();
    });
  }

  if (
    enterpriseAuthProviderBody instanceof HTMLElement &&
    enterpriseAuthProviderStatus instanceof HTMLElement &&
    authProvidersApiPath.length > 0
  ) {
    enterpriseAuthProviderBody.addEventListener('click', async (event) => {
      const target = event.target;

      if (!(target instanceof HTMLElement)) {
        return;
      }

      const editButton = target.closest('[data-enterprise-auth-edit-provider]');

      if (editButton instanceof HTMLElement) {
        fillEnterpriseAuthProviderForm({
          id: editButton.dataset.providerId ?? '',
          protocol: editButton.dataset.providerProtocol ?? 'oidc',
          label: editButton.dataset.providerLabel ?? '',
          enabled: editButton.dataset.providerEnabled === 'true',
          isDefault: editButton.dataset.providerIsDefault === 'true',
          configJson: editButton.dataset.providerConfigJson ?? '{}',
        });
        setStatus(enterpriseAuthProviderStatus, 'Loaded provider into edit form.', false);
        return;
      }

      const deleteButton = target.closest('[data-enterprise-auth-delete-provider-id]');

      if (!(deleteButton instanceof HTMLElement)) {
        return;
      }

      const providerId = deleteButton.dataset.enterpriseAuthDeleteProviderId ?? '';
      const providerLabel = deleteButton.dataset.providerLabel ?? 'this provider';

      if (providerId.length === 0) {
        setStatus(enterpriseAuthProviderStatus, 'Provider ID missing from delete action.', true);
        return;
      }

      if (!window.confirm('Delete ' + providerLabel + '?')) {
        return;
      }

      setStatus(enterpriseAuthProviderStatus, 'Deleting auth provider...', false);

      try {
        const response = await fetch(authProvidersApiPath + '/' + encodeURIComponent(providerId), {
          method: 'DELETE',
        });
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(enterpriseAuthProviderStatus, errorDetailFromPayload(payload), true);
          return;
        }

        setStatus(enterpriseAuthProviderStatus, 'Enterprise auth provider deleted.', false);
        setTimeout(() => {
          window.location.assign(tenantAdminPath);
        }, 900);
      } catch {
        setStatus(enterpriseAuthProviderStatus, 'Unable to delete enterprise auth provider.', true);
      }
    });
  }

  if (
    breakGlassAccountForm instanceof HTMLFormElement &&
    breakGlassAccountStatus instanceof HTMLElement &&
    breakGlassAccountsApiPath.length > 0
  ) {
    breakGlassAccountForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setStatus(breakGlassAccountStatus, 'Adding break-glass account...', false);

      const data = new FormData(breakGlassAccountForm);
      const emailRaw = data.get('email');
      const email = typeof emailRaw === 'string' ? emailRaw.trim() : '';

      if (email.length === 0) {
        setStatus(breakGlassAccountStatus, 'Institution email is required.', true);
        return;
      }

      try {
        const response = await fetch(breakGlassAccountsApiPath, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            email,
            sendEnrollmentEmail: data.get('sendEnrollmentEmail') !== null,
          }),
        });
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(breakGlassAccountStatus, errorDetailFromPayload(payload), true);
          return;
        }

        setStatus(breakGlassAccountStatus, 'Break-glass account saved.', false);
        setTimeout(() => {
          window.location.assign(tenantAdminPath);
        }, 900);
      } catch {
        setStatus(breakGlassAccountStatus, 'Unable to save break-glass account.', true);
      }
    });
  }

  if (
    breakGlassAccountBody instanceof HTMLElement &&
    breakGlassAccountStatus instanceof HTMLElement &&
    breakGlassAccountsApiPath.length > 0
  ) {
    breakGlassAccountBody.addEventListener('click', async (event) => {
      const target = event.target;

      if (!(target instanceof HTMLElement)) {
        return;
      }

      const deleteButton = target.closest('[data-break-glass-delete-user-id]');

      if (!(deleteButton instanceof HTMLElement)) {
        return;
      }

      const userId = deleteButton.dataset.breakGlassDeleteUserId ?? '';
      const email = deleteButton.dataset.breakGlassEmail ?? 'this account';

      if (userId.length === 0) {
        setStatus(breakGlassAccountStatus, 'Break-glass user ID missing from revoke action.', true);
        return;
      }

      if (!window.confirm('Revoke break-glass access for ' + email + '?')) {
        return;
      }

      setStatus(breakGlassAccountStatus, 'Revoking break-glass account...', false);

      try {
        const response = await fetch(
          breakGlassAccountsApiPath + '/' + encodeURIComponent(userId),
          {
            method: 'DELETE',
          },
        );
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(breakGlassAccountStatus, errorDetailFromPayload(payload), true);
          return;
        }

        setStatus(breakGlassAccountStatus, 'Break-glass account revoked.', false);
        setTimeout(() => {
          window.location.assign(tenantAdminPath);
        }, 900);
      } catch {
        setStatus(breakGlassAccountStatus, 'Unable to revoke break-glass account.', true);
      }
    });
  }
`;

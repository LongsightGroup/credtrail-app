export const INSTITUTION_ADMIN_API_KEYS_JS = `
(() => {
  const contextElement = document.getElementById('ct-admin-context');

  if (!(contextElement instanceof HTMLElement)) {
    return;
  }

  let parsedContext;

  try {
    parsedContext = JSON.parse(contextElement.dataset.contextJson ?? '{}');
  } catch {
    return;
  }

  const createApiKeyPath =
    parsedContext && typeof parsedContext.createApiKeyPath === 'string'
      ? parsedContext.createApiKeyPath
      : '';
  const apiKeyForm = document.getElementById('api-key-form');
  const apiKeyStatus = document.getElementById('api-key-status');
  const apiKeySecret = document.getElementById('api-key-secret');
  const apiKeyBody = document.getElementById('api-key-body');
  const apiKeyActiveCount = document.getElementById('api-key-active-count');
  const apiKeyRevokeStatus = document.getElementById('api-key-revoke-status');

  if (createApiKeyPath.length === 0) {
    return;
  }

  const setStatus = (el, text, isError, tone = 'info') => {
    if (!(el instanceof HTMLElement)) {
      return;
    }

    el.textContent = text;
    el.dataset.tone = isError ? 'error' : tone;
  };
  const parseJsonBody = async (response) => {
    try {
      return await response.json();
    } catch {
      return null;
    }
  };
  const errorDetailFromPayload = (payload) => {
    return payload && typeof payload.error === 'string' ? payload.error : 'Request failed';
  };
  const updateApiKeyActiveCount = () => {
    if (!(apiKeyBody instanceof HTMLElement) || !(apiKeyActiveCount instanceof HTMLElement)) {
      return;
    }

    const activeRows = apiKeyBody.querySelectorAll('tr[data-api-key-id]').length;
    apiKeyActiveCount.textContent = 'Active API Keys (' + activeRows + ')';
  };
  const ensureApiKeyEmptyState = () => {
    if (!(apiKeyBody instanceof HTMLElement)) {
      return;
    }

    if (apiKeyBody.querySelector('tr[data-api-key-id]') !== null) {
      return;
    }

    apiKeyBody.innerHTML = '<tr><td colspan="5">No active API keys found.</td></tr>';
  };
  const insertApiKeyRowHtml = (rowHtml) => {
    if (!(apiKeyBody instanceof HTMLElement) || typeof rowHtml !== 'string') {
      return;
    }

    const template = document.createElement('template');
    template.innerHTML = rowHtml.trim();
    const row = template.content.firstElementChild;

    if (!(row instanceof HTMLTableRowElement)) {
      return;
    }

    const apiKeyId = row.dataset.apiKeyId ?? '';

    if (apiKeyId.length === 0) {
      return;
    }

    apiKeyBody.querySelectorAll('td[colspan]').forEach((cell) => {
      const emptyRow = cell.closest('tr');

      if (emptyRow !== null) {
        emptyRow.remove();
      }
    });

    const existing = apiKeyBody.querySelector(
      'tr[data-api-key-id="' + CSS.escape(apiKeyId) + '"]',
    );

    if (existing !== null) {
      existing.remove();
    }

    apiKeyBody.prepend(row);
    updateApiKeyActiveCount();
  };

  if (
    apiKeyForm instanceof HTMLFormElement &&
    apiKeyStatus instanceof HTMLElement &&
    apiKeySecret instanceof HTMLElement
  ) {
    apiKeyForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setStatus(apiKeyStatus, 'Creating API key...', false);
      apiKeySecret.hidden = true;
      apiKeySecret.textContent = '';

      const data = new FormData(apiKeyForm);
      const labelRaw = data.get('label');
      const scopesRaw = data.get('scopes');
      const label = typeof labelRaw === 'string' ? labelRaw.trim() : '';
      const scopeList =
        typeof scopesRaw !== 'string'
          ? []
          : scopesRaw
              .split(',')
              .map((entry) => entry.trim())
              .filter((entry) => entry.length > 0);

      if (label.length === 0) {
        setStatus(apiKeyStatus, 'Label is required.', true);
        return;
      }

      try {
        const response = await fetch(createApiKeyPath, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            label,
            scopes: scopeList,
          }),
        });
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(apiKeyStatus, errorDetailFromPayload(payload), true);
          return;
        }

        const apiKey = payload && typeof payload.apiKey === 'string' ? payload.apiKey : null;
        const rowHtml = payload && typeof payload.rowHtml === 'string' ? payload.rowHtml : '';

        if (apiKey !== null) {
          apiKeySecret.hidden = false;
          apiKeySecret.textContent = 'Store this now. It is shown once:\\n\\n' + apiKey;
        }

        insertApiKeyRowHtml(rowHtml);
        apiKeyForm.reset();
        setStatus(apiKeyStatus, 'API key created. Store the secret before closing this form.', false);
      } catch {
        setStatus(apiKeyStatus, 'Unable to create API key from this browser session.', true);
      }
    });
  }

  if (apiKeyRevokeStatus instanceof HTMLElement) {
    document.addEventListener('click', async (event) => {
      const target = event.target;

      if (!(target instanceof Element)) {
        return;
      }

      const candidate = target.closest('button[data-revoke-api-key-path]');

      if (!(candidate instanceof HTMLButtonElement)) {
        return;
      }

      event.preventDefault();

      const revokePath = candidate.dataset.revokeApiKeyPath;
      const label = candidate.dataset.apiKeyLabel ?? 'API key';

      if (typeof revokePath !== 'string' || revokePath.length === 0) {
        setStatus(apiKeyRevokeStatus, 'Missing revoke path for selected key.', true);
        return;
      }

      if (!window.confirm('Revoke key "' + label + '"? This action cannot be undone.')) {
        return;
      }

      candidate.disabled = true;
      setStatus(apiKeyRevokeStatus, 'Revoking API key...', false);

      try {
        const response = await fetch(revokePath, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
          },
          body: JSON.stringify({}),
        });
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(apiKeyRevokeStatus, errorDetailFromPayload(payload), true);
          candidate.disabled = false;
          return;
        }

        const row = candidate.closest('tr[data-api-key-id]');

        if (row !== null) {
          row.remove();
        }

        updateApiKeyActiveCount();
        ensureApiKeyEmptyState();
        setStatus(apiKeyRevokeStatus, 'API key revoked.', false);
      } catch {
        setStatus(
          apiKeyRevokeStatus,
          'Unable to revoke API key from this browser session.',
          true,
        );
        candidate.disabled = false;
      }
    });
  }
})();
`;

import { ADMIN_STATUS_PILL_CLASS_HELPER_JS } from "../../../admin/admin-status-pill-class";

export const INSTITUTION_ADMIN_LMS_CONNECTIONS_JS = [
  ADMIN_STATUS_PILL_CLASS_HELPER_JS,
  `
(() => {
  const contextElement = document.getElementById('ct-admin-context');

  if (!(contextElement instanceof HTMLElement)) {
    return;
  }

  let parsedContext = {};

  try {
    parsedContext = JSON.parse(contextElement.dataset.contextJson ?? '{}');
  } catch {
    return;
  }

  const lmsConnectionsApiPath =
    parsedContext && typeof parsedContext.lmsConnectionsApiPath === 'string'
      ? parsedContext.lmsConnectionsApiPath
      : '';

  if (lmsConnectionsApiPath.length === 0) {
    return;
  }

  const form = document.getElementById('lms-connection-form');
  const status = document.getElementById('lms-connection-status');
  const panel = document.getElementById('lms-connection-panel');
  const title = document.getElementById('lms-connection-form-title');
  const tableBody = document.getElementById('lms-connection-body');
  const heading = document.getElementById('lms-connection-heading');

  if (!(form instanceof HTMLFormElement) || !(status instanceof HTMLElement)) {
    return;
  }

  const credentialField = form.elements.namedItem('accessToken');

  const setStatus = (message, tone) => {
    status.textContent = message;
    status.dataset.tone = tone;
  };

  const formatProviderLabel = (providerKind) => {
    if (providerKind === 'canvas') {
      return 'Canvas';
    }

    if (providerKind === 'sakai') {
      return 'Sakai';
    }

    return providerKind;
  };

  const formatTimestamp = (value) => {
    if (typeof value !== 'string' || value.length === 0) {
      return 'Not recorded';
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
      return value;
    }

    return date.toLocaleString(undefined, {
      dateStyle: 'medium',
      timeStyle: 'short',
    });
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

  const fieldValue = (name) => {
    const field = form.elements.namedItem(name);

    if (
      field instanceof HTMLInputElement ||
      field instanceof HTMLSelectElement ||
      field instanceof HTMLTextAreaElement
    ) {
      return field.value.trim();
    }

    return '';
  };

  const setFieldValue = (name, value) => {
    const field = form.elements.namedItem(name);

    if (
      field instanceof HTMLInputElement ||
      field instanceof HTMLSelectElement ||
      field instanceof HTMLTextAreaElement
    ) {
      field.value = value;
    }
  };

  const setCredentialPlaceholder = (editing) => {
    if (!(credentialField instanceof HTMLInputElement)) {
      return;
    }

    if (editing) {
      credentialField.placeholder = 'Leave blank to keep existing credential';
      return;
    }

    credentialField.placeholder =
      fieldValue('providerKind') === 'sakai'
        ? 'Paste Sakai SAKAIID session value'
        : 'Paste Canvas access token';
  };

  const appendTextCell = (row, text) => {
    const cell = document.createElement('td');
    cell.textContent = text;
    row.append(cell);
    return cell;
  };

  const bindEditButton = (button) => {
    button.addEventListener('click', () => {
      setFieldValue('connectionId', button.dataset.lmsConnectionEdit ?? '');
      setFieldValue('displayName', button.dataset.lmsConnectionName ?? '');
      setFieldValue('providerKind', button.dataset.lmsConnectionProvider ?? 'canvas');
      setFieldValue('apiBaseUrl', button.dataset.lmsConnectionApiBaseUrl ?? '');
      setFieldValue('ltiIssuer', button.dataset.lmsConnectionLtiIssuer ?? '');
      setFieldValue('ltiClientId', button.dataset.lmsConnectionLtiClientId ?? '');
      setFieldValue('ltiDeploymentId', button.dataset.lmsConnectionLtiDeploymentId ?? '');
      setFieldValue('accessToken', '');
      setFieldValue('refreshToken', '');
      setFieldValue('clientSecret', '');

      if (panel instanceof HTMLDetailsElement) {
        panel.open = true;
      }

      if (title instanceof HTMLElement) {
        title.textContent = 'Edit LMS connection';
      }

      setCredentialPlaceholder(true);
      setStatus('Editing connection details. Leave credential fields blank to keep saved secrets.', 'info');
      const prefersReducedMotion =
        window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      form.scrollIntoView({ block: 'start', behavior: prefersReducedMotion ? 'auto' : 'smooth' });
    });
  };

  const createConnectionRow = (connection) => {
    const row = document.createElement('tr');
    const connected = connection && connection.hasAccessToken === true;

    const nameCell = document.createElement('td');
    const strong = document.createElement('strong');
    strong.textContent =
      connection && typeof connection.displayName === 'string' ? connection.displayName : '';
    const meta = document.createElement('div');
    meta.className = 'ct-admin__meta';
    meta.textContent = connection && typeof connection.id === 'string' ? connection.id : '';
    nameCell.append(strong, meta);
    row.append(nameCell);

    appendTextCell(
      row,
      formatProviderLabel(
        connection && typeof connection.providerKind === 'string' ? connection.providerKind : '',
      ),
    );
    appendTextCell(
      row,
      connection && typeof connection.apiBaseUrl === 'string' ? connection.apiBaseUrl : '',
    );

    const statusCell = document.createElement('td');
    const pill = document.createElement('span');
    pill.className = adminStatusPillClass(connected ? 'active' : 'warning');
    pill.textContent = connected ? 'Connected' : 'Needs token';
    statusCell.append(pill);
    row.append(statusCell);

    appendTextCell(
      row,
      formatTimestamp(
        connection && typeof connection.connectedAt === 'string' ? connection.connectedAt : null,
      ),
    );

    const ltiDetails = [
      connection && typeof connection.ltiIssuer === 'string' && connection.ltiIssuer.length > 0
        ? 'Issuer: ' + connection.ltiIssuer
        : null,
      connection && typeof connection.ltiClientId === 'string' && connection.ltiClientId.length > 0
        ? 'Client: ' + connection.ltiClientId
        : null,
      connection &&
      typeof connection.ltiDeploymentId === 'string' &&
      connection.ltiDeploymentId.length > 0
        ? 'Deployment: ' + connection.ltiDeploymentId
        : null,
    ].filter((value) => typeof value === 'string');
    const ltiCell = document.createElement('td');

    if (ltiDetails.length === 0) {
      const ltiMeta = document.createElement('span');
      ltiMeta.className = 'ct-admin__meta';
      ltiMeta.textContent = 'Not recorded';
      ltiCell.append(ltiMeta);
    } else {
      ltiCell.textContent = ltiDetails.join(' · ');
    }

    row.append(ltiCell);

    const actionCell = document.createElement('td');
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'ct-admin__button ct-admin__button--secondary ct-admin__button--tiny';
    button.textContent = 'Edit';
    button.dataset.lmsConnectionEdit =
      connection && typeof connection.id === 'string' ? connection.id : '';
    button.dataset.lmsConnectionName =
      connection && typeof connection.displayName === 'string' ? connection.displayName : '';
    button.dataset.lmsConnectionProvider =
      connection && typeof connection.providerKind === 'string' ? connection.providerKind : '';
    button.dataset.lmsConnectionApiBaseUrl =
      connection && typeof connection.apiBaseUrl === 'string' ? connection.apiBaseUrl : '';
    button.dataset.lmsConnectionLtiIssuer =
      connection && typeof connection.ltiIssuer === 'string' ? connection.ltiIssuer : '';
    button.dataset.lmsConnectionLtiClientId =
      connection && typeof connection.ltiClientId === 'string' ? connection.ltiClientId : '';
    button.dataset.lmsConnectionLtiDeploymentId =
      connection && typeof connection.ltiDeploymentId === 'string'
        ? connection.ltiDeploymentId
        : '';
    bindEditButton(button);
    actionCell.append(button);
    row.append(actionCell);

    return row;
  };

  const renderConnections = (connections) => {
    if (!(tableBody instanceof HTMLTableSectionElement) || !Array.isArray(connections)) {
      return;
    }

    tableBody.replaceChildren(...connections.map((connection) => createConnectionRow(connection)));

    if (heading instanceof HTMLElement) {
      heading.textContent = 'Current LMS Connections (' + String(connections.length) + ')';
    }
  };

  const upsertRenderedConnection = (connection) => {
    if (!(tableBody instanceof HTMLTableSectionElement)) {
      return;
    }

    const row = createConnectionRow(connection);
    const existingButton = Array.from(
      tableBody.querySelectorAll('[data-lms-connection-edit]'),
    ).find((candidate) => {
      return (
        candidate instanceof HTMLButtonElement &&
        candidate.dataset.lmsConnectionEdit === connection.id
      );
    });
    const existingRow = existingButton instanceof HTMLButtonElement ? existingButton.closest('tr') : null;

    if (existingRow instanceof HTMLTableRowElement) {
      existingRow.replaceWith(row);
    } else {
      const existingRows = Array.from(tableBody.querySelectorAll('tr'));
      const hasOnlyEmptyRow =
        existingRows.length === 1 &&
        existingRows[0] instanceof HTMLTableRowElement &&
        existingRows[0].querySelector('[data-lms-connection-edit]') === null;

      if (hasOnlyEmptyRow) {
        tableBody.replaceChildren(row);
      } else {
        tableBody.append(row);
      }
    }

    if (heading instanceof HTMLElement) {
      heading.textContent =
        'Current LMS Connections (' +
        String(tableBody.querySelectorAll('[data-lms-connection-edit]').length) +
        ')';
    }
  };

  const putOptional = (payload, name) => {
    const value = fieldValue(name);

    if (value.length > 0) {
      payload[name] = value;
    }
  };

  form.addEventListener('submit', async (event) => {
    event.preventDefault();

    if (!form.reportValidity()) {
      return;
    }

    const connectionId = fieldValue('connectionId');
    const payload = {
      displayName: fieldValue('displayName'),
      providerKind: fieldValue('providerKind'),
      apiBaseUrl: fieldValue('apiBaseUrl'),
    };

    [
      'accessToken',
      'refreshToken',
      'authorizationEndpoint',
      'tokenEndpoint',
      'clientId',
      'clientSecret',
      'scope',
      'ltiIssuer',
      'ltiClientId',
      'ltiDeploymentId',
    ].forEach((name) => {
      putOptional(payload, name);
    });

    setStatus(connectionId.length > 0 ? 'Updating LMS connection...' : 'Saving LMS connection...', 'info');

    try {
      const response = await fetch(
        connectionId.length > 0
          ? lmsConnectionsApiPath + '/' + encodeURIComponent(connectionId)
          : lmsConnectionsApiPath,
        {
          method: connectionId.length > 0 ? 'PUT' : 'POST',
          credentials: 'same-origin',
          redirect: 'manual',
          headers: {
            accept: 'application/json',
            'content-type': 'application/json',
          },
          body: JSON.stringify(payload),
        },
      );
      const body = await parseJsonBody(response);

      if (!response.ok) {
        setStatus(errorDetailFromPayload(body), 'error');
        return;
      }

      if (
        !body ||
        typeof body !== 'object' ||
        !body.connection ||
        typeof body.connection !== 'object' ||
        typeof body.connection.id !== 'string'
      ) {
        setStatus(
          'The LMS connection was not saved. Sign in again and retry if this page was open for a while.',
          'error',
        );
        return;
      }

      upsertRenderedConnection(body.connection);
      form.reset();
      setFieldValue('connectionId', '');
      setCredentialPlaceholder(false);

      if (title instanceof HTMLElement) {
        title.textContent = 'Add LMS connection';
      }

      setStatus('LMS connection saved.', 'success');
    } catch {
      setStatus('Unable to save LMS connection from this browser session.', 'error');
    }
  });

  document.querySelectorAll('[data-lms-connection-edit]').forEach((candidate) => {
    if (!(candidate instanceof HTMLButtonElement)) {
      return;
    }

    bindEditButton(candidate);
  });

  const providerField = form.elements.namedItem('providerKind');

  if (providerField instanceof HTMLSelectElement) {
    providerField.addEventListener('change', () => {
      setCredentialPlaceholder(fieldValue('connectionId').length > 0);
    });
  }

  setCredentialPlaceholder(false);
})();
`,
].join("\n");

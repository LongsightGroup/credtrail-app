export const INSTITUTION_ADMIN_ORG_UNITS_JS = `
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

  const tenantAdminPath =
    parsedContext && typeof parsedContext.tenantAdminPath === 'string'
      ? parsedContext.tenantAdminPath
      : '';
  const createOrgUnitPath =
    parsedContext && typeof parsedContext.createOrgUnitPath === 'string'
      ? parsedContext.createOrgUnitPath
      : '';
  const orgUnitForm = document.getElementById('org-unit-form');
  const orgUnitStatus = document.getElementById('org-unit-status');

  if (
    tenantAdminPath.length === 0 ||
    createOrgUnitPath.length === 0 ||
    !(orgUnitForm instanceof HTMLFormElement) ||
    !(orgUnitStatus instanceof HTMLElement)
  ) {
    return;
  }

  const setStatus = (el, text, isError, tone = 'info') => {
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

  const unitTypeInput = orgUnitForm.elements.namedItem('unitType');
  const parentOrgUnitInput = orgUnitForm.elements.namedItem('parentOrgUnitId');
  const requiredParentTypeByUnitType = {
    institution: null,
    college: 'institution',
    department: 'college',
    program: 'department',
  };

  const syncParentOptions = () => {
    if (!(unitTypeInput instanceof HTMLSelectElement)) {
      return;
    }

    if (!(parentOrgUnitInput instanceof HTMLSelectElement)) {
      return;
    }

    const unitType = unitTypeInput.value;
    const requiredParentType = requiredParentTypeByUnitType[unitType];

    Array.from(parentOrgUnitInput.options).forEach((option) => {
      if (option.value.length === 0) {
        option.hidden = false;
        option.disabled = false;
        option.textContent = requiredParentType === null ? 'None' : 'Select parent';
        return;
      }

      const parentType = option.dataset.unitType ?? null;
      const matches = requiredParentType === null || parentType === requiredParentType;
      option.hidden = !matches;
      option.disabled = !matches;
    });

    const selected = parentOrgUnitInput.selectedOptions.item(0);

    if (selected !== null && selected.value.length > 0 && (selected.hidden || selected.disabled)) {
      parentOrgUnitInput.value = '';
    }
  };

  syncParentOptions();

  if (unitTypeInput instanceof HTMLSelectElement) {
    unitTypeInput.addEventListener('change', syncParentOptions);
  }

  orgUnitForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    setStatus(orgUnitStatus, 'Creating org unit...', false);
    const data = new FormData(orgUnitForm);
    const unitTypeRaw = data.get('unitType');
    const displayNameRaw = data.get('displayName');
    const parentOrgUnitIdRaw = data.get('parentOrgUnitId');
    const unitType = typeof unitTypeRaw === 'string' ? unitTypeRaw.trim() : '';
    const displayName = typeof displayNameRaw === 'string' ? displayNameRaw.trim() : '';
    const parentOrgUnitId =
      typeof parentOrgUnitIdRaw === 'string' ? parentOrgUnitIdRaw.trim() : '';

    if (unitType.length === 0 || displayName.length === 0) {
      setStatus(orgUnitStatus, 'Unit type and display name are required.', true);
      return;
    }

    const requiredParentType = requiredParentTypeByUnitType[unitType] ?? null;

    if (requiredParentType !== null && parentOrgUnitId.length === 0) {
      setStatus(orgUnitStatus, 'Selected unit type requires a parent org unit.', true);
      return;
    }

    try {
      const response = await fetch(createOrgUnitPath, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          unitType,
          displayName,
          ...(parentOrgUnitId.length > 0 ? { parentOrgUnitId } : {}),
        }),
      });
      const payload = await parseJsonBody(response);

      if (!response.ok) {
        setStatus(orgUnitStatus, errorDetailFromPayload(payload), true);
        return;
      }

      setStatus(orgUnitStatus, 'Org unit created.', false);
      setTimeout(() => {
        window.location.assign(tenantAdminPath);
      }, 900);
    } catch {
      setStatus(orgUnitStatus, 'Unable to create org unit from this browser session.', true);
    }
  });
})();
`;

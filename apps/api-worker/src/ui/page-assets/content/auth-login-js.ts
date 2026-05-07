export const AUTH_LOGIN_JS = `
(() => {
  const form = document.getElementById('magic-link-login-form');
  const statusEl = document.getElementById('magic-link-login-status');
  const devLinkEl = document.getElementById('magic-link-dev-link');
  const turnstileEl = document.getElementById('magic-link-turnstile');
  let turnstileWidgetId = null;

  if (!(form instanceof HTMLFormElement) || !(statusEl instanceof HTMLElement) || !(devLinkEl instanceof HTMLElement)) {
    return;
  }

  const setStatus = (text, tone) => {
    statusEl.hidden = false;
    statusEl.textContent = text;
    statusEl.dataset.tone = tone;
  };

  const ensureTurnstile = () => {
    if (!(turnstileEl instanceof HTMLElement)) {
      return;
    }

    turnstileEl.hidden = false;

    if (turnstileWidgetId !== null || !window.turnstile || typeof window.turnstile.render !== 'function') {
      return;
    }

    turnstileWidgetId = window.turnstile.render(turnstileEl, {
      sitekey: turnstileEl.dataset.sitekey,
    });
  };

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    setStatus('Sending your sign-in link...', 'info');
    devLinkEl.textContent = '';
    const data = new FormData(form);
    const tenantIdRaw = data.get('tenantId');
    const emailRaw = data.get('email');
    const nextRaw = data.get('next');
    const turnstileRaw = data.get('cf-turnstile-response');
    const tenantId = typeof tenantIdRaw === 'string' ? tenantIdRaw.trim() : '';
    const email = typeof emailRaw === 'string' ? emailRaw.trim().toLowerCase() : '';
    const next = typeof nextRaw === 'string' ? nextRaw.trim() : '';
    const turnstileToken = typeof turnstileRaw === 'string' ? turnstileRaw.trim() : '';

    if (tenantId.length === 0 || email.length === 0) {
      setStatus('Enter both your tenant ID and institution email.', 'error');
      return;
    }

    try {
      const response = await fetch('/v1/auth/magic-link/request', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          tenantId,
          email,
          ...(turnstileToken.length === 0 ? {} : { turnstileToken }),
        }),
      });
      const payload = await response.json().catch(() => null);

      if (!response.ok) {
        if (payload && payload.turnstileRequired === true) {
          ensureTurnstile();
        }
        const detail = payload && typeof payload.error === 'string' ? payload.error : 'Request failed';
        setStatus(detail, 'error');
        return;
      }

      const deliveryStatus =
        payload && typeof payload.deliveryStatus === 'string'
          ? payload.deliveryStatus
          : 'sent';
      setStatus(
        deliveryStatus === 'sent'
          ? 'Check your inbox for a sign-in link from CredTrail. It expires in 10 minutes.'
          : deliveryStatus === 'failed'
            ? 'Your sign-in link was created, but the email could not be delivered. Contact support.'
            : 'Your sign-in link is ready.',
        deliveryStatus === 'failed' ? 'error' : 'success',
      );

      if (payload && typeof payload.magicLinkUrl === 'string' && payload.magicLinkUrl.length > 0) {
        const url = new URL(payload.magicLinkUrl);
        if (next.length > 0 && next.startsWith('/')) {
          url.searchParams.set('next', next);
        }
        devLinkEl.innerHTML = '<a href="' + url.toString() + '">Open sign-in link (development helper)</a>';
      }
    } catch {
      setStatus('We could not send the sign-in link right now. Please try again.', 'error');
    }
  });
})();
`;

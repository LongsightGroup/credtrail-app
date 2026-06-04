export const PUBLIC_BADGE_JS = `
(() => {
  const heroImages = document.querySelectorAll('.public-badge__hero-image');

  for (const image of heroImages) {
    if (!(image instanceof HTMLImageElement)) {
      continue;
    }

    image.addEventListener('error', () => {
      const fallback = image.dataset.fallbackSrc;

      if (typeof fallback === 'string' && fallback.length > 0 && image.src !== fallback) {
        image.src = fallback;
        delete image.dataset.fallbackSrc;
        return;
      }

      image.hidden = true;
      image.parentElement?.setAttribute('data-fallback', 'true');
    });
  }

  const copyBadgeButton = document.getElementById('copy-badge-url-button');
  const copyBadgeStatus = document.getElementById('copy-badge-url-status');

  if (copyBadgeButton instanceof HTMLButtonElement && copyBadgeStatus instanceof HTMLElement) {
    const value = copyBadgeButton.dataset.copyValue;

    if (typeof value === 'string' && value.length > 0) {
      copyBadgeButton.addEventListener('click', async () => {
        try {
          await navigator.clipboard.writeText(value);
          copyBadgeStatus.textContent = 'Public URL copied';
        } catch {
          copyBadgeStatus.textContent = 'Unable to copy public URL automatically';
        }
      });
    }
  }

  const chapiButton = document.getElementById('chapi-store-button');
  const chapiStatus = document.getElementById('chapi-store-status');

  if (chapiButton instanceof HTMLButtonElement && chapiStatus instanceof HTMLElement) {
    const credentialJsonUrl = chapiButton.dataset.credentialJsonUrl;

    if (typeof credentialJsonUrl === 'string' && credentialJsonUrl.length > 0) {
      chapiButton.addEventListener('click', async () => {
        const credentialsApi = navigator.credentials;

        if (credentialsApi === undefined || typeof credentialsApi.store !== 'function') {
          chapiStatus.textContent = 'Browser wallet API unavailable; use Download .jsonld VC.';
          return;
        }

        try {
          const response = await fetch(credentialJsonUrl, {
            headers: {
              accept: 'application/vc+ld+json, application/ld+json, application/json',
            },
          });

          if (!response.ok) {
            chapiStatus.textContent = 'Unable to load credential for browser wallet import.';
            return;
          }

          const credential = await response.json();

          await credentialsApi.store({
            type: 'OpenBadgeCredential',
            credential,
          });
          chapiStatus.textContent = 'Credential sent to browser wallet.';
        } catch {
          chapiStatus.textContent = 'Browser wallet import failed; use Download .jsonld VC.';
        }
      });
    }
  }

  const copyWallButtons = document.querySelectorAll('.badge-wall__button[data-copy-value]');

  for (const button of copyWallButtons) {
    if (!(button instanceof HTMLButtonElement)) {
      continue;
    }

    const copyValue = button.dataset.copyValue;
    const status = button.closest('.badge-wall__item')?.querySelector('.badge-wall__copy-status');

    if (typeof copyValue !== 'string' || copyValue.length === 0 || !(status instanceof HTMLElement)) {
      continue;
    }

    button.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(copyValue);
        status.textContent = 'Copied link';
      } catch {
        status.textContent = 'Unable to copy automatically';
      }
    });
  }
})();
`;

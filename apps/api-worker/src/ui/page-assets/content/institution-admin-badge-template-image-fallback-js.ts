export const INSTITUTION_ADMIN_BADGE_TEMPLATE_IMAGE_FALLBACK_JS = `
  const initAdminImageFallbacks = () => {
    document.querySelectorAll('[data-admin-image-fallback]').forEach((frame) => {
      if (!(frame instanceof HTMLElement)) {
        return;
      }

      const link = frame.querySelector('[data-admin-image-link]');
      const image = frame.querySelector('[data-admin-image]');
      const placeholder = frame.querySelector('[data-admin-image-placeholder]');

      if (
        !(link instanceof HTMLElement) ||
        !(image instanceof HTMLImageElement) ||
        !(placeholder instanceof HTMLElement)
      ) {
        return;
      }

      const showPlaceholder = () => {
        link.hidden = true;
        placeholder.hidden = false;
        frame.dataset.adminImageFallback = 'unavailable';
      };

      if (image.complete && image.naturalWidth === 0) {
        showPlaceholder();
        return;
      }

      image.addEventListener('error', showPlaceholder, { once: true });
    });
  };

  initAdminImageFallbacks();
`;

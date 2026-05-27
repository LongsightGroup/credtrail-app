export const INSTITUTION_ADMIN_SHELL_JS = `
(() => {
  const sidebarToggle = document.querySelector('[data-sidebar-toggle]');
  const sidebar = document.querySelector('.ct-admin-sidebar');

  if (sidebarToggle instanceof HTMLElement && sidebar instanceof HTMLElement) {
    sidebarToggle.addEventListener('click', () => {
      sidebar.classList.toggle('ct-admin-sidebar--open');
    });

    document.addEventListener('click', (event) => {
      if (
        sidebar.classList.contains('ct-admin-sidebar--open') &&
        !sidebar.contains(event.target) &&
        event.target !== sidebarToggle
      ) {
        sidebar.classList.remove('ct-admin-sidebar--open');
      }
    });
  }

  const actionMenuGap = 4;
  const viewportPadding = 8;

  const findActionMenuTrigger = (popover) => {
    if (!(popover instanceof HTMLElement) || popover.id.length === 0) {
      return null;
    }

    for (const candidate of document.querySelectorAll('[popovertarget]')) {
      if (
        candidate instanceof HTMLElement &&
        candidate.getAttribute('popovertarget') === popover.id
      ) {
        return candidate;
      }
    }

    return null;
  };

  const positionActionMenuPopover = (popover, trigger) => {
    if (!(popover instanceof HTMLElement) || !(trigger instanceof HTMLElement)) {
      return;
    }

    const triggerRect = trigger.getBoundingClientRect();
    const popoverRect = popover.getBoundingClientRect();
    const popoverWidth = Math.max(popoverRect.width, 0);
    const popoverHeight = Math.max(popoverRect.height, 0);
    const minLeft = viewportPadding;
    const maxLeft = Math.max(minLeft, window.innerWidth - popoverWidth - viewportPadding);
    const preferredLeft = triggerRect.right - popoverWidth;
    const minTop = viewportPadding;
    const maxTop = Math.max(minTop, window.innerHeight - popoverHeight - viewportPadding);
    const belowTop = triggerRect.bottom + actionMenuGap;
    const aboveTop = triggerRect.top - popoverHeight - actionMenuGap;
    const hasBelowSpace = belowTop + popoverHeight <= window.innerHeight - viewportPadding;
    const hasAboveSpace = aboveTop >= viewportPadding;
    const preferredTop = hasBelowSpace || !hasAboveSpace ? belowTop : aboveTop;

    popover.style.position = 'fixed';
    popover.style.top = Math.min(Math.max(preferredTop, minTop), maxTop) + 'px';
    popover.style.left = Math.min(Math.max(preferredLeft, minLeft), maxLeft) + 'px';
    popover.style.right = 'auto';
    popover.style.bottom = 'auto';
  };

  const closeActionMenuPopover = (element) => {
    if (!(element instanceof Element)) {
      return;
    }

    const popover = element.closest('.ct-admin__action-menu-popover');
    if (popover instanceof HTMLElement && typeof popover.hidePopover === 'function') {
      popover.hidePopover();
    }
  };

  document.addEventListener('toggle', (event) => {
    const popover = event.target;

    if (
      !(popover instanceof HTMLElement) ||
      !popover.classList.contains('ct-admin__action-menu-popover') ||
      event.newState !== 'open'
    ) {
      return;
    }

    const trigger = findActionMenuTrigger(popover);
    if (trigger instanceof HTMLElement) {
      positionActionMenuPopover(popover, trigger);
    }
  });

  window.CredTrailAdminActionMenus = {
    close: closeActionMenuPopover,
    position: positionActionMenuPopover,
  };
})();
`;

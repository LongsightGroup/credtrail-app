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
  let openActionMenuPopover = null;
  let openActionMenuTrigger = null;

  const findActionMenuPanel = (trigger) => {
    if (!(trigger instanceof HTMLElement)) {
      return null;
    }

    const menuId = trigger.getAttribute('data-action-menu-trigger') || '';
    if (menuId.length === 0) {
      return null;
    }

    const candidate = document.getElementById(menuId);
    return candidate instanceof HTMLElement ? candidate : null;
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

  const closeOpenActionMenuPopover = () => {
    if (openActionMenuPopover instanceof HTMLElement) {
      openActionMenuPopover.hidden = true;
      openActionMenuPopover.removeAttribute('data-open');
    }

    if (openActionMenuTrigger instanceof HTMLElement) {
      openActionMenuTrigger.setAttribute('aria-expanded', 'false');
    }

    openActionMenuPopover = null;
    openActionMenuTrigger = null;
  };

  const openActionMenu = (trigger, popover) => {
    closeOpenActionMenuPopover();

    popover.hidden = false;
    popover.setAttribute('data-open', 'true');
    trigger.setAttribute('aria-expanded', 'true');
    openActionMenuPopover = popover;
    openActionMenuTrigger = trigger;
    positionActionMenuPopover(popover, trigger);
  };

  const toggleActionMenu = (trigger, popover) => {
    if (openActionMenuPopover === popover) {
      closeOpenActionMenuPopover();
      return;
    }

    openActionMenu(trigger, popover);
  };

  const closeActionMenuPopover = (element) => {
    if (!(element instanceof Element)) {
      return;
    }

    const popover = element.closest('.ct-admin__action-menu-popover');
    if (popover instanceof HTMLElement && popover === openActionMenuPopover) {
      closeOpenActionMenuPopover();
    }
  };

  document.addEventListener('click', (event) => {
    const target = event.target;

    if (!(target instanceof Element)) {
      return;
    }

    const trigger = target.closest('[data-action-menu-trigger]');
    if (trigger instanceof HTMLElement) {
      const popover = findActionMenuPanel(trigger);
      if (popover instanceof HTMLElement) {
        event.preventDefault();
        event.stopPropagation();
        toggleActionMenu(trigger, popover);
      }
      return;
    }

    if (
      openActionMenuPopover instanceof HTMLElement &&
      !openActionMenuPopover.contains(target)
    ) {
      closeOpenActionMenuPopover();
    }
  });

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      closeOpenActionMenuPopover();
    }
  });

  document.addEventListener(
    'scroll',
    () => {
      closeOpenActionMenuPopover();
    },
    { capture: true, passive: true },
  );

  window.CredTrailAdminActionMenus = {
    close: closeActionMenuPopover,
    position: positionActionMenuPopover,
  };
})();
`;

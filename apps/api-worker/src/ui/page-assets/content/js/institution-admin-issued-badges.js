const parsedContext = readAdminContext();

if (!parsedContext) {
  return;
}

document.addEventListener("click", (event) => {
  const target = event.target;

  if (!(target instanceof HTMLElement)) {
    return;
  }

  const menuLink = target.closest("a.ct-admin__action-menu-item");

  if (menuLink instanceof HTMLAnchorElement) {
    menuLink.closest("details")?.removeAttribute("open");
  }
});

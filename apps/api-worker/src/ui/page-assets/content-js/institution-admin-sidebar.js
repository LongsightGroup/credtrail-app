(() => {
  const sidebarToggle = document.querySelector("[data-sidebar-toggle]");
  const sidebar = document.querySelector(".ct-admin-sidebar");

  if (sidebarToggle instanceof HTMLElement && sidebar instanceof HTMLElement) {
    sidebarToggle.addEventListener("click", () => {
      sidebar.classList.toggle("ct-admin-sidebar--open");
    });

    document.addEventListener("click", (event) => {
      if (
        sidebar.classList.contains("ct-admin-sidebar--open") &&
        !sidebar.contains(event.target) &&
        event.target !== sidebarToggle
      ) {
        sidebar.classList.remove("ct-admin-sidebar--open");
      }
    });
  }
})();

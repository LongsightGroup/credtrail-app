(() => {
const readAdminContext = () => {
  const contextElement = document.getElementById("ct-admin-context");

  if (!(contextElement instanceof HTMLElement)) {
    return null;
  }

  const contextJson =
    contextElement.dataset.contextJson ??
    (contextElement instanceof HTMLScriptElement ? contextElement.textContent : null) ??
    "{}";

  try {
    const parsedContext = JSON.parse(contextJson);

    return parsedContext && typeof parsedContext === "object" ? parsedContext : null;
  } catch {
    return null;
  }
};

const setStatus = (el, text, isError, tone = "info") => {
  if (!(el instanceof HTMLElement)) {
    return;
  }

  el.textContent = text;
  el.dataset.tone = isError ? "error" : tone;
};

const parseJsonBody = async (response) => {
  try {
    return await response.json();
  } catch {
    return null;
  }
};

const errorDetailFromPayload = (payload) => {
  return payload && typeof payload.error === "string" ? payload.error : "Request failed";
};

const setCodeOutput = (el, value) => {
  if (!(el instanceof HTMLElement)) {
    return;
  }

  if (typeof value !== "string" || value.length === 0) {
    el.hidden = true;
    el.textContent = "";
    return;
  }

  el.hidden = false;
  el.textContent = value;
};

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

})();
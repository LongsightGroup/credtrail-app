const updateTrustEdRepeatableTemplateTokens = (root, rowIndex) => {
  const rowNumber = String(rowIndex + 1);
  const index = String(rowIndex);
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  let textNode = walker.nextNode();

  while (textNode !== null) {
    textNode.textContent = (textNode.textContent || "")
      .replaceAll("__INDEX__", index)
      .replaceAll("__ROW_NUMBER__", rowNumber);
    textNode = walker.nextNode();
  }

  root.querySelectorAll("*").forEach((element) => {
    for (const attribute of Array.from(element.attributes)) {
      if (attribute.value.includes("__INDEX__") || attribute.value.includes("__ROW_NUMBER__")) {
        element.setAttribute(
          attribute.name,
          attribute.value.replaceAll("__INDEX__", index).replaceAll("__ROW_NUMBER__", rowNumber),
        );
      }
    }
  });
};
const renumberTrustEdRepeatableRows = (group) => {
  group.querySelectorAll("[data-trusted-repeatable-row]").forEach((row, index) => {
    if (!(row instanceof HTMLElement)) {
      return;
    }

    const label = row.querySelector(
      ".ct-admin__template-editor-trusted-repeatable-row-header span",
    );

    row.dataset.trustedRepeatableIndex = String(index);

    if (label instanceof HTMLElement) {
      const groupTitle =
        group.dataset.trustedRepeatableTitle ??
        group
          .querySelector(".ct-admin__template-editor-trusted-repeatable-summary strong")
          ?.textContent?.trim() ??
        "Entry";
      label.textContent = groupTitle + " " + String(index + 1);
    }

    row.querySelectorAll("input, textarea").forEach((control) => {
      if (!(control instanceof HTMLInputElement) && !(control instanceof HTMLTextAreaElement)) {
        return;
      }

      control.name = control.name.replace(/\[\d+\]/, "[" + String(index) + "]");
    });
  });
};
document.addEventListener("click", (event) => {
  const target = event.target;

  if (!(target instanceof Element)) {
    return;
  }

  const addButton = target.closest("[data-trusted-repeatable-add]");

  if (addButton instanceof HTMLElement) {
    const groupName = addButton.dataset.trustedRepeatableAdd;
    const group =
      typeof groupName === "string"
        ? document.querySelector('[data-trusted-repeatable="' + groupName + '"]')
        : null;

    if (!(group instanceof HTMLElement)) {
      return;
    }

    const template = group.querySelector("template[data-trusted-repeatable-template]");
    const rows = group.querySelector(".ct-admin__template-editor-trusted-repeatable-rows");

    if (!(template instanceof HTMLTemplateElement) || !(rows instanceof HTMLElement)) {
      return;
    }

    const nextIndex = Number.parseInt(group.dataset.trustedRepeatableNextIndex || "0", 10);
    const safeNextIndex = Number.isFinite(nextIndex) ? nextIndex : rows.children.length;
    const fragment = template.content.cloneNode(true);

    updateTrustEdRepeatableTemplateTokens(fragment, safeNextIndex);
    rows.appendChild(fragment);
    group.dataset.trustedRepeatableNextIndex = String(safeNextIndex + 1);

    const addedRows = rows.querySelectorAll("[data-trusted-repeatable-row]");
    const addedRow = addedRows[addedRows.length - 1];
    const firstControl =
      addedRow instanceof HTMLElement ? addedRow.querySelector("input, textarea") : null;

    if (firstControl instanceof HTMLElement) {
      firstControl.focus();
    }
    return;
  }

  const removeButton = target.closest("[data-trusted-repeatable-remove]");

  if (removeButton instanceof HTMLElement) {
    const row = removeButton.closest("[data-trusted-repeatable-row]");
    const group = removeButton.closest("[data-trusted-repeatable]");

    if (row instanceof HTMLElement && group instanceof HTMLElement) {
      row.remove();
      renumberTrustEdRepeatableRows(group);
    }
  }
});

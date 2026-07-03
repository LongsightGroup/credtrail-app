const printButton = document.getElementById("assertion-evidence-print");
const downloadButton = document.getElementById("assertion-evidence-download-json");

if (printButton instanceof HTMLButtonElement) {
  printButton.addEventListener("click", () => {
    window.print();
  });
}

if (downloadButton instanceof HTMLButtonElement) {
  downloadButton.addEventListener("click", async () => {
    const evidenceApiPath = downloadButton.dataset.evidenceApiPath?.trim() ?? "";

    if (evidenceApiPath.length === 0) {
      return;
    }

    try {
      const response = await fetch(evidenceApiPath, {
        method: "GET",
        headers: {
          accept: "application/json",
        },
      });

      if (!response.ok) {
        return;
      }

      const payload = await response.json();
      const blob = new Blob([JSON.stringify(payload, null, 2)], {
        type: "application/json",
      });
      const objectUrl = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = objectUrl;
      anchor.download = "credential-evidence.json";
      anchor.click();
      URL.revokeObjectURL(objectUrl);
    } catch {
      // Download failures are non-blocking for the printable report view.
    }
  });
}

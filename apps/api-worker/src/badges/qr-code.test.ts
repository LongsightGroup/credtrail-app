import { describe, expect, it } from "vitest";

import { createQrCodeMatrix, renderQrCodeSvg } from "./qr-code";

describe("QR code helpers", () => {
  it("creates a square matrix for QR rendering targets", () => {
    const matrix = createQrCodeMatrix("https://credtrail.org/badges/example");

    expect(matrix.moduleCount).toBeGreaterThan(0);
    expect(matrix.modules).toHaveLength(matrix.moduleCount);
    expect(matrix.modules.every((row) => row.length === matrix.moduleCount)).toBe(true);
    expect(matrix.modules.some((row) => row.some((module) => module))).toBe(true);
  });

  it("renders an SVG QR code", () => {
    const svg = renderQrCodeSvg("https://credtrail.org/badges/example");

    expect(svg.startsWith("<?xml") || svg.includes("<svg")).toBe(true);
    expect(svg).toContain("<svg");
    expect(svg).toContain("</svg>");
  });
});

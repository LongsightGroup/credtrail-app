import { describe, expect, it } from "vitest";
import { adminStatusPillClass } from "./admin-status-pill-class";

describe("adminStatusPillClass", () => {
  it("returns base class when tone is empty", () => {
    expect(adminStatusPillClass(null)).toBe("ct-admin__status-pill");
    expect(adminStatusPillClass("   ")).toBe("ct-admin__status-pill");
  });

  it("returns tone modifier class when tone is set", () => {
    expect(adminStatusPillClass("active")).toBe(
      "ct-admin__status-pill ct-admin__status-pill--active",
    );
  });
});

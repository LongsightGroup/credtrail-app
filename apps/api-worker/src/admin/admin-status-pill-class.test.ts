import { describe, expect, it } from "vitest";
import { createContext, Script } from "node:vm";
import {
  adminStatusPillClass,
  renderAdminStatusPillClassBrowserHelper,
} from "./admin-status-pill-class";

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

  it("matches the generated browser helper", () => {
    const context = createContext({});
    new Script(renderAdminStatusPillClassBrowserHelper()).runInContext(context);
    const browserHelper = (context as { adminStatusPillClass?: (tone: unknown) => string })
      .adminStatusPillClass;

    expect(typeof browserHelper).toBe("function");
    expect(browserHelper?.(null)).toBe(adminStatusPillClass(null));
    expect(browserHelper?.("active")).toBe(adminStatusPillClass("active"));
  });
});

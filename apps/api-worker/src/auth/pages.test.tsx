import { describe, expect, it } from "vitest";
import { renderAppPageToString } from "../ui/render-page";
import { localBreakGlassLoginPage, magicLinkLoginPage } from "./pages";

describe("auth pages", () => {
  it("renders magic-link login fields with form primitives", () => {
    const html = renderAppPageToString(
      magicLinkLoginPage({
        tenantId: "tenant_123",
        nextPath: "/tenants/tenant_123/admin",
      }),
    );

    expect(html).toContain('id="magic-link-login-form"');
    expect(html).toContain("ct-login__form ct-stack ct-form");
    expect(html).toContain("ct-login__field ct-stack ct-field");
    expect(html).toContain("ct-input ct-field__control");
    expect(html).toContain('name="email"');
    expect(html).toContain('type="email"');
    expect(html).toContain('placeholder="name@institution.edu"');
    expect(html).toContain("required");
    expect(html).toContain('name="tenantId"');
    expect(html).toContain('name="next"');
  });

  it("renders local login credential fields with form primitives", () => {
    const html = renderAppPageToString(
      localBreakGlassLoginPage({
        tenantId: "tenant_123",
        nextPath: "/tenants/tenant_123/admin",
      }),
    );

    expect(html).toContain('action="/auth/local/sign-in"');
    expect(html).toContain("ct-login__form ct-stack ct-form");
    expect(html).toContain("ct-login__field ct-stack ct-field");
    expect(html).toContain('name="email"');
    expect(html).toContain('type="email"');
    expect(html).toContain('name="password"');
    expect(html).toContain('type="password"');
    expect(html).toContain('placeholder="Your local break-glass password"');
  });
});

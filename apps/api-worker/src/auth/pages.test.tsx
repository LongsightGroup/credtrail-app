import { describe, expect, it } from "vitest";
import { renderAppPageToString } from "../ui/render-page";
import { localBreakGlassLoginPage, magicLinkConfirmationPage, magicLinkLoginPage } from "./pages";

describe("auth pages", () => {
  it("confirms that the user signed out", () => {
    const html = renderAppPageToString(
      magicLinkLoginPage({
        tenantId: "",
        nextPath: "",
        reason: "signed_out",
      }),
    );

    expect(html).toContain("You are signed out.");
  });

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

  it("renders magic-link confirmation as a server-side POST form", () => {
    const html = renderAppPageToString(
      magicLinkConfirmationPage({
        token: "token-with-<unsafe>-characters",
        nextPath: "/auth/resolve",
      }),
    );

    expect(html).toContain('action="/auth/magic-link/verify"');
    expect(html).toContain('method="post"');
    expect(html).toContain('name="token"');
    expect(html).toContain('value="token-with-&lt;unsafe&gt;-characters"');
    expect(html).toContain('name="next" type="hidden" value="/auth/resolve"');
    expect(html).toContain("Continue to CredTrail");
    expect(html).not.toContain("onclick=");
  });
});

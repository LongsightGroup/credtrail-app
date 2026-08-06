import { parseMagicLinkVerifyRequest } from "@credtrail/validation";
import type { Hono } from "hono";
import type { AppContext, AppEnv } from "../app";
import type { AuthenticatedPrincipal, RequestedTenantContext } from "../auth/auth-context";
import { magicLinkConfirmationPage } from "../auth/pages";
import { normalizeSafeRedirectPath } from "../auth/redirect-paths";
import { appPage, renderAppPage } from "../ui/render-page";

const MAGIC_LINK_FALLBACK_PATH = "/auth/resolve";

const getFormValue = (formData: FormData, name: string): string => {
  const raw = formData.get(name);
  return typeof raw === "string" ? raw.trim() : "";
};

const renderInvalidMagicLink = (
  c: AppContext,
  input: {
    title: "Invalid Magic Link" | "Expired Magic Link";
    heading: "Invalid magic link" | "Magic link expired";
    message: string;
  },
): Response | Promise<Response> => {
  return renderAppPage(
    c,
    appPage({
      title: input.title,
      body: (
        <>
          <h1>{input.heading}</h1>
          <p>{input.message}</p>
        </>
      ),
    }),
    400,
  );
};

const parseToken = (token: string): string | null => {
  try {
    return parseMagicLinkVerifyRequest({ token }).token;
  } catch {
    return null;
  }
};

/** Registers the non-consuming browser confirmation and consuming POST for magic links. */
export const registerMagicLinkBrowserRoutes = (input: {
  app: Hono<AppEnv>;
  createMagicLinkSession: (c: AppContext, token: string) => Promise<AuthenticatedPrincipal | null>;
  resolveRequestedTenantContext: (c: AppContext) => Promise<RequestedTenantContext | null>;
}): void => {
  input.app.get("/auth/magic-link/verify", (c) => {
    const token = parseToken(c.req.query("token")?.trim() ?? "");

    if (token === null) {
      return renderInvalidMagicLink(c, {
        title: "Invalid Magic Link",
        heading: "Invalid magic link",
        message: "The link is incomplete. Request a new sign-in link.",
      });
    }

    return renderAppPage(
      c,
      magicLinkConfirmationPage({
        token,
        nextPath: normalizeSafeRedirectPath(c.req.query("next"), MAGIC_LINK_FALLBACK_PATH),
      }),
    );
  });

  input.app.post("/auth/magic-link/verify", async (c) => {
    const formData = await c.req.formData();
    const token = parseToken(getFormValue(formData, "token"));

    if (token === null) {
      return renderInvalidMagicLink(c, {
        title: "Invalid Magic Link",
        heading: "Invalid magic link",
        message: "The link is incomplete. Request a new sign-in link.",
      });
    }

    const principal = await input.createMagicLinkSession(c, token);

    if (principal === null) {
      return renderInvalidMagicLink(c, {
        title: "Expired Magic Link",
        heading: "Magic link expired",
        message: "The link is invalid or expired. Request a new sign-in link.",
      });
    }

    const requestedTenant = await input.resolveRequestedTenantContext(c);

    if (requestedTenant === null) {
      return renderAppPage(
        c,
        appPage({
          title: "Sign-in Error",
          body: (
            <>
              <h1>Unable to complete sign-in</h1>
              <p>Please request a new sign-in link.</p>
            </>
          ),
        }),
        500,
      );
    }

    return c.redirect(
      normalizeSafeRedirectPath(getFormValue(formData, "next"), MAGIC_LINK_FALLBACK_PATH),
      302,
    );
  });
};

import { expect, test, type Page } from "@playwright/test";

import {
  createLiveRulePlacementAvailabilityFixture,
  type LiveLtiPlatform,
} from "./helpers/live-rule-placement-availability-fixture";

const ltiLoginUrl = (
  baseURL: string,
  platform: LiveLtiPlatform,
  input: {
    readonly targetLinkUri: string;
    readonly messageHint: Readonly<Record<string, unknown>>;
  },
): string => {
  const url = new URL("/v1/lti/oidc/login", baseURL);
  url.searchParams.set("iss", platform.issuer);
  url.searchParams.set("client_id", platform.clientId);
  url.searchParams.set("login_hint", "stable-rule-instructor");
  url.searchParams.set("target_link_uri", input.targetLinkUri);
  url.searchParams.set("lti_deployment_id", platform.deploymentId);
  url.searchParams.set("lti_message_hint", JSON.stringify(input.messageHint));
  return url.toString();
};

const launchResourceLink = async (
  page: Page,
  input: {
    readonly baseURL: string;
    readonly platform: LiveLtiPlatform;
    readonly targetLinkUri: string;
    readonly custom: Readonly<Record<string, string>>;
    readonly contextId: string;
    readonly contextTitle: string;
    readonly resourceLinkId: string;
  },
): Promise<void> => {
  await page.goto(
    ltiLoginUrl(input.baseURL, input.platform, {
      targetLinkUri: input.targetLinkUri,
      messageHint: {
        kind: "resource",
        contextId: input.contextId,
        contextTitle: input.contextTitle,
        resourceLinkId: input.resourceLinkId,
        targetLinkUri: input.targetLinkUri,
        custom: input.custom,
      },
    }),
  );
  await expect(
    page.getByRole("heading", { name: /CredTrail could not load this LMS roster/i }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "This badge rule isn’t available in this course" }),
  ).toHaveCount(0);
};

test("a governed stable rule survives an LMS course copy into a new term", async ({
  browser,
  baseURL,
}) => {
  if (baseURL === undefined) {
    throw new Error("Playwright baseURL is required.");
  }

  const fixture = await createLiveRulePlacementAvailabilityFixture();
  const context = await browser.newContext();

  try {
    const page = await context.newPage();
    const adminLoginUrl = new URL("/v1/dev/auth/login-as", baseURL);
    adminLoginUrl.searchParams.set("tenantId", fixture.tenantId);
    adminLoginUrl.searchParams.set("email", fixture.adminEmail);
    adminLoginUrl.searchParams.set("next", fixture.rulesPath);
    await page.goto(adminLoginUrl.toString());

    const ruleRow = page.locator("tbody tr").filter({ hasText: fixture.ruleName });
    await ruleRow
      .getByRole("link", { name: `Set course availability for ${fixture.ruleName}` })
      .click();
    await page.getByRole("radio", { name: /Every course in this institution/ }).check();
    await page.getByLabel("I have reviewed the institution-wide impact.").check();
    await page.getByRole("button", { name: "Update course availability" }).click();
    await expect(
      page.getByText("Every course in this institution", { exact: true }).first(),
    ).toBeVisible();

    const launchTarget = new URL("/v1/lti/launch", baseURL).toString();
    await page.goto(
      ltiLoginUrl(baseURL, fixture.ltiPlatform, {
        targetLinkUri: launchTarget,
        messageHint: {
          kind: "deep-link",
          contextId: "fall-2026-course",
          contextTitle: "Community Data — Fall 2026",
          targetLinkUri: launchTarget,
        },
      }),
    );
    await expect(page.getByRole("heading", { name: "Add a badge rule" })).toBeVisible();
    await expect(page.getByRole("heading", { name: fixture.ruleName })).toBeVisible();
    await page.getByRole("button", { name: "Add to this course" }).click();
    await expect(page.getByRole("heading", { name: "Content added to course" })).toBeVisible();

    const contentItem = fixture.ltiPlatform.readContentItem();
    expect(contentItem.title).toBe(fixture.ruleName);
    expect(new URL(contentItem.url).searchParams.get("ruleId")).toBe(contentItem.custom.ruleId);
    expect(new URL(contentItem.url).searchParams.get("badgeTemplateId")).toBe(
      contentItem.custom.badgeTemplateId,
    );

    await launchResourceLink(page, {
      baseURL,
      platform: fixture.ltiPlatform,
      targetLinkUri: contentItem.url,
      custom: contentItem.custom,
      contextId: "fall-2026-course",
      contextTitle: "Community Data — Fall 2026",
      resourceLinkId: "stable-badge-link-fall-2026",
    });
    await launchResourceLink(page, {
      baseURL,
      platform: fixture.ltiPlatform,
      targetLinkUri: contentItem.url,
      custom: contentItem.custom,
      contextId: "spring-2027-course",
      contextTitle: "Community Data — Spring 2027",
      resourceLinkId: "stable-badge-link-spring-2027",
    });

    await expect(fixture.readPlacementContexts()).resolves.toEqual([
      "fall-2026-course",
      "spring-2027-course",
    ]);
    await expect(fixture.readRuleState()).resolves.toEqual(fixture.initialRuleState);
  } finally {
    await context.close();
    await fixture.dispose();
  }
});

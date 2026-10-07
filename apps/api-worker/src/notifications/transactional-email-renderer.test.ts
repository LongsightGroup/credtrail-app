import { expect, it } from "vitest";
import type { TransactionalEmailContent } from "./transactional-email-content";
import { renderTransactionalEmail } from "./transactional-email-renderer";

const content = {
  institution: 'University & <script>alert("unsafe")</script> 学習',
  title: "Your achievement",
  paragraphs: ["First line\nSecond line"],
  details: [{ label: "Reviewer comment", value: '<img src=x onerror="alert(1)">' }],
  action: { label: "View your badge", url: "https://badges.example.edu/badges/123?a=1&b=2" },
  secondaryActions: [{ label: "Download", url: "https://badges.example.edu/badges/123/download" }],
  footer: "Contact your institution.",
} satisfies TransactionalEmailContent;

it("escapes institution names and comments while preserving equivalent text and links", async () => {
  const result = await renderTransactionalEmail(content);
  expect(result.html).not.toContain("<script>");
  expect(result.html).not.toContain("<img");
  expect(result.html).toContain("&lt;script&gt;");
  expect(result.html).toContain("&lt;img");
  expect(result.html).toContain("a=1&amp;b=2");
  expect(result.text).toContain(content.institution);
  expect(result.text).toContain(content.details[0]?.value);
  expect(result.text).toContain(content.action.url);
  expect(result.html).toContain(content.secondaryActions[0]?.url);
  for (const value of ["学習", "First line", "Second line", content.footer]) {
    expect(result.html).toContain(value);
    expect(result.text).toContain(value);
  }
});

it("rejects unsafe primary and secondary links without exposing tokens", async () => {
  for (const url of [
    "javascript:private-auth-token",
    "data:text/html,private-auth-token",
    "not-a-url-private-auth-token",
  ]) {
    await expect(
      renderTransactionalEmail({ ...content, action: { label: "Continue", url } }),
    ).rejects.toThrow("Transactional email content is invalid");
    await expect(
      renderTransactionalEmail({ ...content, secondaryActions: [{ label: "Continue", url }] }),
    ).rejects.toThrow("Transactional email content is invalid");
  }
});

it("keeps concurrent institutions isolated without shared mutable template state", async () => {
  const institutions = ["North University", "South College"];
  const results = await Promise.all(
    institutions.map((institution) => renderTransactionalEmail({ ...content, institution })),
  );
  expect(results[0]?.html).toContain("North University");
  expect(results[0]?.text).not.toContain("South College");
  expect(results[1]?.html).toContain("South College");
  expect(results[1]?.text).not.toContain("North University");
});

it("defaults optional document lists without changing its action", async () => {
  const result = await renderTransactionalEmail({
    institution: "Example University",
    title: "Sign in",
    paragraphs: ["Use this link once."],
    action: content.action,
    footer: content.footer,
  });
  expect(result.text).toContain(content.action.url);
  expect(result.html).toContain("View your badge");
  expect(result.html).not.toContain("<dl");
});

it("rejects unsafe image sources without exposing input values", async () => {
  for (const url of [
    "javascript:private-token",
    "http://localhost/private-token",
    "https://user:private-token@example.edu/image",
  ]) {
    await expect(
      renderTransactionalEmail({ ...content, image: { url, alt: "Badge artwork" } }),
    ).rejects.toThrow("Transactional email content is invalid");
  }
});

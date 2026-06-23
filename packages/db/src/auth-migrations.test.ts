import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

describe("better auth core migration", () => {
  it("keeps Better Auth tables in an auth schema and preserves CredTrail-owned tables", () => {
    const sql = readFileSync(
      new URL("../migrations/0025_better_auth_core.sql", import.meta.url),
      "utf8",
    );

    expect(sql).toContain("CREATE SCHEMA IF NOT EXISTS auth");
    expect(sql).toContain("CREATE TABLE IF NOT EXISTS auth.user");
    expect(sql).toContain("CREATE TABLE IF NOT EXISTS auth.session");
    expect(sql).toContain("CREATE TABLE IF NOT EXISTS auth.account");
    expect(sql).toContain("CREATE TABLE IF NOT EXISTS auth.verification");
    expect(sql).toContain("CREATE TABLE IF NOT EXISTS auth_identity_links");
    expect(sql).not.toContain("CREATE TABLE IF NOT EXISTS users");
    expect(sql).not.toContain("CREATE TABLE IF NOT EXISTS sessions");
  });

  it("adds tenant auth policy and provider migrations", () => {
    const policySql = readFileSync(
      new URL("../migrations/0026_tenant_auth_policies.sql", import.meta.url),
      "utf8",
    );
    const providerSql = readFileSync(
      new URL("../migrations/0027_tenant_auth_providers.sql", import.meta.url),
      "utf8",
    );

    expect(policySql).toContain("CREATE TABLE IF NOT EXISTS tenant_auth_policies");
    expect(policySql).toContain("CHECK (login_mode IN ('local', 'hybrid', 'sso_required'))");
    expect(providerSql).toContain("CREATE TABLE IF NOT EXISTS tenant_auth_providers");
    expect(providerSql).toContain("idx_tenant_auth_providers_default_per_tenant");
  });

  it("drops tenant SAML SSO configuration and restricts auth providers to OIDC", () => {
    const sql = readFileSync(
      new URL("../migrations/0048_drop_tenant_sso_saml_configurations.sql", import.meta.url),
      "utf8",
    );

    expect(sql).toContain("DELETE FROM tenant_auth_providers");
    expect(sql).toContain("DROP TABLE IF EXISTS tenant_sso_saml_configurations");
    expect(sql).toContain("CHECK (protocol IN ('oidc'))");
  });

  it("adds Better Auth enterprise SSO indexes without changing CredTrail-owned tables", () => {
    const ssoSql = readFileSync(
      new URL("../migrations/0029_better_auth_enterprise_sso.sql", import.meta.url),
      "utf8",
    );

    expect(ssoSql).toContain("idx_auth_user_email");
    expect(ssoSql).toContain("idx_auth_account_provider_user");
    expect(ssoSql).not.toContain("CREATE TABLE IF NOT EXISTS tenant_auth_providers");
  });

  it("removes legacy auth table helpers from the public DB package", async () => {
    const dbModule = await import("./index");

    expect(dbModule).not.toHaveProperty("createMagicLinkToken");
    expect(dbModule).not.toHaveProperty("findMagicLinkTokenByHash");
    expect(dbModule).not.toHaveProperty("markMagicLinkTokenUsed");
    expect(dbModule).not.toHaveProperty("createSession");
    expect(dbModule).not.toHaveProperty("findActiveSessionByHash");
    expect(dbModule).not.toHaveProperty("touchSession");
    expect(dbModule).not.toHaveProperty("revokeSessionByHash");
  });

  it("adds a forward migration that drops obsolete legacy auth tables and indexes", () => {
    const sql = readFileSync(
      new URL("../migrations/0032_drop_legacy_auth_tables.sql", import.meta.url),
      "utf8",
    );

    expect(sql).toContain("DROP INDEX IF EXISTS idx_magic_link_tokens_tenant_user");
    expect(sql).toContain("DROP INDEX IF EXISTS idx_magic_link_tokens_expires_at");
    expect(sql).toContain("DROP INDEX IF EXISTS idx_sessions_tenant_user");
    expect(sql).toContain("DROP INDEX IF EXISTS idx_sessions_expires_at");
    expect(sql).toContain("DROP TABLE IF EXISTS magic_link_tokens");
    expect(sql).toContain("DROP TABLE IF EXISTS sessions");
  });

  it("adds Better Auth two-factor and tenant break-glass migrations", () => {
    const twoFactorSql = readFileSync(
      new URL("../migrations/0030_better_auth_two_factor.sql", import.meta.url),
      "utf8",
    );
    const breakGlassSql = readFileSync(
      new URL("../migrations/0031_tenant_break_glass_accounts.sql", import.meta.url),
      "utf8",
    );

    expect(twoFactorSql).toContain("ALTER TABLE auth.user");
    expect(twoFactorSql).toContain("two_factor_enabled");
    expect(twoFactorSql).toContain("CREATE TABLE IF NOT EXISTS auth.two_factor");
    expect(breakGlassSql).toContain("CREATE TABLE IF NOT EXISTS tenant_break_glass_accounts");
    expect(breakGlassSql).toContain("last_enrollment_email_sent_at");
    expect(breakGlassSql).toContain("idx_tenant_break_glass_accounts_tenant_active");
  });

  it("adds LTI issuer NRPS credential columns through a forward migration", () => {
    const sql = readFileSync(
      new URL("../migrations/0039_lti_issuer_registration_nrps_credentials.sql", import.meta.url),
      "utf8",
    );

    expect(sql).toContain("ALTER TABLE lti_issuer_registrations");
    expect(sql).toContain("ADD COLUMN IF NOT EXISTS token_endpoint TEXT");
    expect(sql).toContain("ADD COLUMN IF NOT EXISTS client_secret TEXT");
  });

  it("drops obsolete unsigned LTI launch compatibility through a forward migration", () => {
    const sql = readFileSync(
      new URL("../migrations/0041_drop_lti_allow_unsigned_id_token.sql", import.meta.url),
      "utf8",
    );

    expect(sql).toContain("ALTER TABLE lti_issuer_registrations");
    expect(sql).toContain("DROP COLUMN IF EXISTS allow_unsigned_id_token");
  });

  it("adds badge template image revision and generation tables", () => {
    const sql = readFileSync(
      new URL("../migrations/0042_badge_template_image_design.sql", import.meta.url),
      "utf8",
    );

    expect(sql).toContain("CREATE TABLE IF NOT EXISTS badge_template_image_revisions");
    expect(sql).toContain("CREATE TABLE IF NOT EXISTS badge_template_image_generations");
    expect(sql).toContain("generate_badge_template_image");
  });
});

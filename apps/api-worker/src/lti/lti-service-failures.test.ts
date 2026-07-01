import { LtiServiceError } from "@longsightgroup/lti-tool";
import { LtiIssuerTenantConflictError } from "@credtrail/db";
import { describe, expect, it } from "vitest";
import { ltiServiceErrorIndicatesIssuerTenantConflict } from "./lti-service-failures";

describe("ltiServiceErrorIndicatesIssuerTenantConflict", () => {
  it("returns true when the service error cause is an issuer tenant conflict", () => {
    const conflict = new LtiIssuerTenantConflictError(
      "https://canvas.test",
      "tenant-a",
      "tenant-b",
    );
    const error = new LtiServiceError({
      code: "platform_request_failed",
      serviceKind: "dynamic_registration",
      operation: "completeDynamicRegistration",
      message: conflict.message,
      cause: conflict,
    });

    expect(ltiServiceErrorIndicatesIssuerTenantConflict(error)).toBe(true);
  });

  it("returns true when the conflict is nested inside another service error", () => {
    const conflict = new LtiIssuerTenantConflictError(
      "https://canvas.test",
      "tenant-a",
      "tenant-b",
    );
    const inner = new LtiServiceError({
      code: "platform_request_failed",
      serviceKind: "dynamic_registration",
      operation: "completeDynamicRegistration",
      message: conflict.message,
      cause: conflict,
    });
    const outer = new LtiServiceError({
      code: "platform_request_failed",
      serviceKind: "dynamic_registration",
      operation: "completeDynamicRegistration",
      message: inner.message,
      cause: inner,
    });

    expect(ltiServiceErrorIndicatesIssuerTenantConflict(outer)).toBe(true);
  });

  it("returns false for unrelated service failures", () => {
    const error = new LtiServiceError({
      code: "platform_request_failed",
      serviceKind: "dynamic_registration",
      operation: "completeDynamicRegistration",
      message: "Invalid or expired registration session",
      cause: new Error("Invalid or expired registration session"),
    });

    expect(ltiServiceErrorIndicatesIssuerTenantConflict(error)).toBe(false);
  });
});

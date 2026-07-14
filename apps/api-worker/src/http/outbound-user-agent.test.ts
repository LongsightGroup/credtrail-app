import { describe, expect, it } from "vitest";
import { CREDTRAIL_OUTBOUND_USER_AGENT, withCredTrailUserAgent } from "./outbound-user-agent";

describe("withCredTrailUserAgent", () => {
  it("adds CredTrail's identity without dropping existing headers", () => {
    const headers = withCredTrailUserAgent({ accept: "application/json" });

    expect(headers.get("accept")).toBe("application/json");
    expect(headers.get("user-agent")).toBe(CREDTRAIL_OUTBOUND_USER_AGENT);
  });

  it("preserves an explicitly supplied user agent", () => {
    const headers = withCredTrailUserAgent({ "user-agent": "CredTrail health check" });

    expect(headers.get("user-agent")).toBe("CredTrail health check");
  });
});

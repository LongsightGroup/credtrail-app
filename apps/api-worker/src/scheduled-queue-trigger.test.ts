import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    leaseJobQueueMessages: vi.fn(),
  };
});

vi.mock("@credtrail/db/postgres", () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

import { leaseJobQueueMessages, type SqlDatabase } from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";

import worker from "./index";

const mockedLeaseJobQueueMessages = vi.mocked(leaseJobQueueMessages);
const mockedCreatePostgresDatabase = vi.mocked(createPostgresDatabase);
const fakeDb = {
  prepare: vi.fn(),
} as unknown as SqlDatabase;

const createEnv = (): {
  APP_ENV: string;
  DATABASE_URL: string;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
  PUBLIC_APP_ORIGIN: string;
  JOB_PROCESSOR_TOKEN?: string;
} => {
  return {
    APP_ENV: "test",
    DATABASE_URL: "postgres://credtrail-test.local/db",
    BADGE_OBJECTS: {} as R2Bucket,
    PLATFORM_DOMAIN: "credtrail.test",
    PUBLIC_APP_ORIGIN: "https://credtrail.test",
  };
};

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
  mockedLeaseJobQueueMessages.mockReset();
});

describe("scheduled queue processor trigger", () => {
  it("processes queued jobs directly on schedule", async () => {
    mockedLeaseJobQueueMessages.mockResolvedValue([]);

    await worker.scheduled?.(
      {
        cron: "* * * * *",
        scheduledTime: Date.now(),
        type: "scheduled",
        noRetry: vi.fn(),
      } as unknown as ScheduledController,
      createEnv(),
      {
        waitUntil: vi.fn(),
        passThroughOnException: vi.fn(),
      } as unknown as ExecutionContext,
    );

    expect(mockedLeaseJobQueueMessages).toHaveBeenCalledTimes(1);
  });
});

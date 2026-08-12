import type { SqlDatabase } from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AppBindings } from "./types";
import { resolveDatabase } from "./database";

vi.mock("@credtrail/db/postgres", () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

const mockedCreatePostgresDatabase = vi.mocked(createPostgresDatabase);
const fakeDatabase = {} as SqlDatabase;

const bindings = (input: Partial<AppBindings>): AppBindings => {
  return {
    APP_ENV: "test",
    BADGE_OBJECTS: {} as AppBindings["BADGE_OBJECTS"],
    PLATFORM_DOMAIN: "credtrail.test",
    PUBLIC_APP_ORIGIN: "https://credtrail.test",
    ...input,
  };
};

describe("resolveDatabase", () => {
  beforeEach(() => {
    mockedCreatePostgresDatabase.mockReset();
    mockedCreatePostgresDatabase.mockReturnValue(fakeDatabase);
  });

  it("uses Hyperdrive with single-use connections when the binding is present", () => {
    const database = resolveDatabase(
      bindings({
        APP_ENV: "production",
        DATABASE_URL: "postgres://direct.example/db",
        HYPERDRIVE: {
          connectionString: "postgres://hyperdrive.example/db",
        } as Hyperdrive,
      }),
    );

    expect(database).toBe(fakeDatabase);
    expect(mockedCreatePostgresDatabase).toHaveBeenCalledWith({
      databaseUrl: "postgres://hyperdrive.example/db",
      connectionMode: "single-use",
    });
  });

  it("requires Hyperdrive in production", () => {
    expect(() =>
      resolveDatabase(
        bindings({
          APP_ENV: "production",
          DATABASE_URL: "postgres://direct.example/db",
        }),
      ),
    ).toThrowError("HYPERDRIVE is required in production");
  });

  it("keeps DATABASE_URL fallback outside production", () => {
    const database = resolveDatabase(
      bindings({
        APP_ENV: "test",
        DATABASE_URL: "postgres://direct.example/db",
      }),
    );

    expect(database).toBe(fakeDatabase);
    expect(mockedCreatePostgresDatabase).toHaveBeenCalledWith({
      databaseUrl: "postgres://direct.example/db",
      connectionMode: "pool",
    });
  });
});

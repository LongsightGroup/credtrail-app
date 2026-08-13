# Postgres migrations

Migration SQL files are append-only production artifacts. After a migration is
committed, do not edit, rename, reorder, or delete it. Add a new migration with
a version that sorts after the current highest version.

The Postgres migration runner stores the SHA-256 checksum of each applied file
in `schema_migrations`. Existing installations receive a one-time checksum
baseline. Later runs fail before applying new SQL when an applied migration was
changed or removed, or when a new file was inserted into applied history.

Add the SHA-256 checksum for every new migration to `checksums.json`. The runner
verifies the committed manifest before connecting to Postgres, so an unrecorded
or changed file also fails in a fresh environment.

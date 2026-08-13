ALTER TABLE assertions
  ADD COLUMN achievement_snapshot_status TEXT;

UPDATE assertions
SET achievement_snapshot_status = CASE
  WHEN achievement_snapshot_json IS NULL THEN 'unavailable'
  ELSE 'captured'
END;

ALTER TABLE assertions
  ALTER COLUMN achievement_snapshot_json DROP NOT NULL,
  ALTER COLUMN achievement_snapshot_status SET DEFAULT 'captured',
  ALTER COLUMN achievement_snapshot_status SET NOT NULL,
  ADD CONSTRAINT assertions_achievement_snapshot_status_check
    CHECK (achievement_snapshot_status IN ('captured', 'unavailable')),
  ADD CONSTRAINT assertions_achievement_snapshot_state_check
    CHECK (
      (
        achievement_snapshot_status = 'captured'
        AND achievement_snapshot_json IS NOT NULL
      )
      OR
      (
        achievement_snapshot_status = 'unavailable'
        AND achievement_snapshot_json IS NULL
      )
    );

-- Remove the superseded template-level LTI placement policy and delegation action.

UPDATE badge_templates
SET governance_metadata_json = CASE
  WHEN governance_metadata_json IS NULL THEN NULL
  ELSE (governance_metadata_json::JSONB - 'ltiInstructorPlacement')::TEXT
END,
updated_at = CURRENT_TIMESTAMP
WHERE governance_metadata_json IS NOT NULL
  AND governance_metadata_json::JSONB ? 'ltiInstructorPlacement';

UPDATE delegated_issuing_authority_grants
SET allowed_actions_json = (
  SELECT COALESCE(JSONB_AGG(action ORDER BY action), '[]'::JSONB)::TEXT
  FROM JSONB_ARRAY_ELEMENTS_TEXT(allowed_actions_json::JSONB) AS actions(action)
  WHERE action <> 'configure_course_rule'
),
updated_at = CURRENT_TIMESTAMP
WHERE allowed_actions_json::JSONB ? 'configure_course_rule';

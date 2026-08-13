ALTER TABLE learner_pathway_completion_handoffs
  DROP CONSTRAINT learner_pathway_completion_handoffs_status_check,
  ADD COLUMN issued_assertion_id TEXT,
  ADD COLUMN issued_at TEXT,
  ADD CONSTRAINT learner_pathway_completion_handoffs_status_check
    CHECK (status IN ('recorded', 'eligible', 'review_pending', 'issued', 'cancelled')),
  ADD CONSTRAINT learner_pathway_completion_handoffs_issued_assertion_fk
    FOREIGN KEY (tenant_id, issued_assertion_id)
    REFERENCES assertions (tenant_id, id)
    DEFERRABLE INITIALLY DEFERRED,
  ADD CONSTRAINT learner_pathway_completion_handoffs_issuance_check
    CHECK (
      (status = 'issued' AND issued_assertion_id IS NOT NULL AND issued_at IS NOT NULL)
      OR (status <> 'issued' AND issued_assertion_id IS NULL AND issued_at IS NULL)
    );

CREATE INDEX idx_learner_pathway_handoffs_assertion
  ON learner_pathway_completion_handoffs (tenant_id, issued_assertion_id)
  WHERE issued_assertion_id IS NOT NULL;

ALTER TABLE learner_pathway_completion_handoffs
  DROP CONSTRAINT learner_pathway_completion_handoffs_issued_assertion_fk,
  ADD CONSTRAINT learner_pathway_completion_handoffs_issued_assertion_fk
    FOREIGN KEY (tenant_id, issued_assertion_id)
    REFERENCES assertions (tenant_id, id) ON DELETE CASCADE
    DEFERRABLE INITIALLY DEFERRED;

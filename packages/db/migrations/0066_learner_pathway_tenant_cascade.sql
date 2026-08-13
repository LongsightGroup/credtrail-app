CREATE OR REPLACE FUNCTION prevent_published_pathway_version_changes()
RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF EXISTS (
      SELECT 1 FROM learner_pathways
      WHERE tenant_id = OLD.tenant_id AND id = OLD.pathway_id
    ) THEN
      RAISE EXCEPTION 'published pathway versions are immutable';
    END IF;
    RETURN OLD;
  END IF;

  IF OLD.status IN ('published', 'superseded') THEN
    IF NOT (
      OLD.status = 'published'
      AND NEW.status = 'superseded'
      AND OLD.id IS NOT DISTINCT FROM NEW.id
      AND OLD.tenant_id IS NOT DISTINCT FROM NEW.tenant_id
      AND OLD.pathway_id IS NOT DISTINCT FROM NEW.pathway_id
      AND OLD.version_number IS NOT DISTINCT FROM NEW.version_number
      AND OLD.title IS NOT DISTINCT FROM NEW.title
      AND OLD.learner_description IS NOT DISTINCT FROM NEW.learner_description
      AND OLD.completion_behavior IS NOT DISTINCT FROM NEW.completion_behavior
      AND OLD.final_badge_template_id IS NOT DISTINCT FROM NEW.final_badge_template_id
      AND OLD.created_by_user_id IS NOT DISTINCT FROM NEW.created_by_user_id
      AND OLD.published_by_user_id IS NOT DISTINCT FROM NEW.published_by_user_id
      AND OLD.published_at IS NOT DISTINCT FROM NEW.published_at
      AND OLD.created_at IS NOT DISTINCT FROM NEW.created_at
    ) THEN
      RAISE EXCEPTION 'published pathway versions are immutable';
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

ALTER TABLE learner_pathways
  ADD CONSTRAINT learner_pathways_tenant_fk
  FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE;

ALTER TABLE learner_pathways
  DROP CONSTRAINT learner_pathways_tenant_id_owner_org_unit_id_fkey,
  ADD CONSTRAINT learner_pathways_owner_org_unit_fk
    FOREIGN KEY (tenant_id, owner_org_unit_id)
    REFERENCES tenant_org_units (tenant_id, id)
    DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE learner_pathways
  DROP CONSTRAINT learner_pathways_current_version_fk,
  ADD CONSTRAINT learner_pathways_current_version_fk
    FOREIGN KEY (tenant_id, current_published_version_id)
    REFERENCES learner_pathway_versions (tenant_id, id)
    DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE learner_pathway_versions
  DROP CONSTRAINT learner_pathway_versions_tenant_id_final_badge_template_id_fkey,
  ADD CONSTRAINT learner_pathway_versions_final_badge_template_fk
    FOREIGN KEY (tenant_id, final_badge_template_id)
    REFERENCES badge_templates (tenant_id, id)
    DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE learner_pathway_requirements
  DROP CONSTRAINT learner_pathway_requirements_tenant_id_badge_template_id_fkey,
  ADD CONSTRAINT learner_pathway_requirements_badge_template_fk
    FOREIGN KEY (tenant_id, badge_template_id)
    REFERENCES badge_templates (tenant_id, id)
    DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE learner_pathway_enrollments
  DROP CONSTRAINT learner_pathway_enrollments_tenant_id_pathway_id_fkey,
  ADD CONSTRAINT learner_pathway_enrollments_pathway_fk
    FOREIGN KEY (tenant_id, pathway_id)
    REFERENCES learner_pathways (tenant_id, id) ON DELETE CASCADE,
  DROP CONSTRAINT learner_pathway_enrollments_tenant_id_pathway_version_id_fkey,
  ADD CONSTRAINT learner_pathway_enrollments_version_fk
    FOREIGN KEY (tenant_id, pathway_version_id)
    REFERENCES learner_pathway_versions (tenant_id, id)
    DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE learner_pathway_waivers
  DROP CONSTRAINT learner_pathway_waivers_tenant_id_requirement_id_fkey,
  ADD CONSTRAINT learner_pathway_waivers_requirement_fk
    FOREIGN KEY (tenant_id, requirement_id)
    REFERENCES learner_pathway_requirements (tenant_id, id)
    DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE learner_pathway_evaluations
  DROP CONSTRAINT learner_pathway_evaluations_tenant_id_pathway_version_id_fkey,
  ADD CONSTRAINT learner_pathway_evaluations_version_fk
    FOREIGN KEY (tenant_id, pathway_version_id)
    REFERENCES learner_pathway_versions (tenant_id, id)
    DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE learner_pathway_completion_handoffs
  DROP CONSTRAINT learner_pathway_completion_han_tenant_id_badge_template_id_fkey,
  ADD CONSTRAINT learner_pathway_completion_handoffs_badge_template_fk
    FOREIGN KEY (tenant_id, badge_template_id)
    REFERENCES badge_templates (tenant_id, id)
    DEFERRABLE INITIALLY DEFERRED;

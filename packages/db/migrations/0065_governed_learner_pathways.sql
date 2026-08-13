CREATE TABLE IF NOT EXISTS learner_pathways (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  owner_org_unit_id TEXT NOT NULL,
  current_published_version_id TEXT,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'retired')),
  created_by_user_id TEXT NOT NULL,
  retired_by_user_id TEXT,
  retired_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, owner_org_unit_id)
    REFERENCES tenant_org_units (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (created_by_user_id) REFERENCES users (id) ON DELETE RESTRICT,
  FOREIGN KEY (retired_by_user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS learner_pathway_versions (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  pathway_id TEXT NOT NULL,
  version_number INTEGER NOT NULL CHECK (version_number > 0),
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'superseded')),
  title TEXT NOT NULL,
  learner_description TEXT NOT NULL,
  completion_behavior TEXT NOT NULL
    CHECK (completion_behavior IN ('mark_complete', 'credential_eligible', 'review_required')),
  final_badge_template_id TEXT,
  created_by_user_id TEXT NOT NULL,
  published_by_user_id TEXT,
  published_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, pathway_id, version_number),
  FOREIGN KEY (tenant_id, pathway_id)
    REFERENCES learner_pathways (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, final_badge_template_id)
    REFERENCES badge_templates (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (created_by_user_id) REFERENCES users (id) ON DELETE RESTRICT,
  FOREIGN KEY (published_by_user_id) REFERENCES users (id) ON DELETE SET NULL,
  CHECK (
    (completion_behavior = 'mark_complete' AND final_badge_template_id IS NULL)
    OR (completion_behavior IN ('credential_eligible', 'review_required') AND final_badge_template_id IS NOT NULL)
  ),
  CHECK (
    (status = 'draft' AND published_at IS NULL)
    OR (status IN ('published', 'superseded') AND published_at IS NOT NULL)
  )
);

ALTER TABLE learner_pathways
  ADD CONSTRAINT learner_pathways_current_version_fk
  FOREIGN KEY (tenant_id, current_published_version_id)
  REFERENCES learner_pathway_versions (tenant_id, id) ON DELETE RESTRICT;

CREATE TABLE IF NOT EXISTS learner_pathway_requirements (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  pathway_version_id TEXT NOT NULL,
  position INTEGER NOT NULL CHECK (position > 0),
  title TEXT NOT NULL,
  description TEXT,
  requirement_kind TEXT NOT NULL CHECK (requirement_kind IN ('badge_template', 'learner_record')),
  badge_template_id TEXT,
  learner_record_type TEXT,
  created_at TEXT NOT NULL,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, pathway_version_id, position),
  FOREIGN KEY (tenant_id, pathway_version_id)
    REFERENCES learner_pathway_versions (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, badge_template_id)
    REFERENCES badge_templates (tenant_id, id) ON DELETE RESTRICT,
  CHECK (
    (requirement_kind = 'badge_template' AND badge_template_id IS NOT NULL AND learner_record_type IS NULL)
    OR (requirement_kind = 'learner_record' AND badge_template_id IS NULL AND learner_record_type IN (
      'course', 'certificate', 'license', 'competency', 'work_based_learning',
      'experience', 'membership', 'custom'
    ))
  )
);

CREATE TABLE IF NOT EXISTS learner_pathway_enrollments (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  pathway_id TEXT NOT NULL,
  pathway_version_id TEXT NOT NULL,
  learner_profile_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'completed', 'withdrawn')),
  enrolled_by_user_id TEXT NOT NULL,
  enrolled_at TEXT NOT NULL,
  completed_at TEXT,
  withdrawn_at TEXT,
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, pathway_id, learner_profile_id),
  FOREIGN KEY (tenant_id, pathway_id)
    REFERENCES learner_pathways (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, pathway_version_id)
    REFERENCES learner_pathway_versions (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, learner_profile_id)
    REFERENCES learner_profiles (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (enrolled_by_user_id) REFERENCES users (id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS learner_pathway_waivers (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  enrollment_id TEXT NOT NULL,
  requirement_id TEXT NOT NULL,
  reason TEXT NOT NULL,
  approved_by_user_id TEXT NOT NULL,
  approved_at TEXT NOT NULL,
  revoked_by_user_id TEXT,
  revoked_at TEXT,
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, enrollment_id)
    REFERENCES learner_pathway_enrollments (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, requirement_id)
    REFERENCES learner_pathway_requirements (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (approved_by_user_id) REFERENCES users (id) ON DELETE RESTRICT,
  FOREIGN KEY (revoked_by_user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_learner_pathway_active_waiver
  ON learner_pathway_waivers (tenant_id, enrollment_id, requirement_id)
  WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS learner_pathway_evaluations (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  enrollment_id TEXT NOT NULL,
  pathway_version_id TEXT NOT NULL,
  sequence_number INTEGER NOT NULL CHECK (sequence_number > 0),
  result TEXT NOT NULL CHECK (result IN ('in_progress', 'needs_review', 'complete', 'invalidated')),
  requirement_results_json TEXT NOT NULL,
  qualifying_evidence_ids_json TEXT NOT NULL,
  rationale TEXT NOT NULL,
  evaluated_at TEXT NOT NULL,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, enrollment_id, sequence_number),
  FOREIGN KEY (tenant_id, enrollment_id)
    REFERENCES learner_pathway_enrollments (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, pathway_version_id)
    REFERENCES learner_pathway_versions (tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS learner_pathway_completion_handoffs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  enrollment_id TEXT NOT NULL,
  evaluation_id TEXT NOT NULL,
  behavior TEXT NOT NULL
    CHECK (behavior IN ('mark_complete', 'credential_eligible', 'review_required')),
  badge_template_id TEXT,
  status TEXT NOT NULL CHECK (status IN ('recorded', 'eligible', 'review_pending', 'cancelled')),
  created_at TEXT NOT NULL,
  resolved_by_user_id TEXT,
  resolved_at TEXT,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, evaluation_id),
  FOREIGN KEY (tenant_id, enrollment_id)
    REFERENCES learner_pathway_enrollments (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, evaluation_id)
    REFERENCES learner_pathway_evaluations (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, badge_template_id)
    REFERENCES badge_templates (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (resolved_by_user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_learner_pathways_tenant_status
  ON learner_pathways (tenant_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_learner_pathway_versions_pathway
  ON learner_pathway_versions (tenant_id, pathway_id, version_number DESC);
CREATE INDEX IF NOT EXISTS idx_learner_pathway_requirements_version
  ON learner_pathway_requirements (tenant_id, pathway_version_id, position);
CREATE INDEX IF NOT EXISTS idx_learner_pathway_enrollments_learner
  ON learner_pathway_enrollments (tenant_id, learner_profile_id, status, enrolled_at DESC);
CREATE INDEX IF NOT EXISTS idx_learner_pathway_evaluations_enrollment
  ON learner_pathway_evaluations (tenant_id, enrollment_id, sequence_number DESC);
CREATE INDEX IF NOT EXISTS idx_learner_pathway_handoffs_status
  ON learner_pathway_completion_handoffs (tenant_id, status, created_at DESC);

CREATE OR REPLACE FUNCTION prevent_published_pathway_version_changes()
RETURNS TRIGGER AS $$
BEGIN
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

DROP TRIGGER IF EXISTS trg_prevent_published_pathway_version_changes
  ON learner_pathway_versions;
CREATE TRIGGER trg_prevent_published_pathway_version_changes
BEFORE UPDATE OR DELETE ON learner_pathway_versions
FOR EACH ROW EXECUTE FUNCTION prevent_published_pathway_version_changes();

CREATE OR REPLACE FUNCTION prevent_published_pathway_requirement_changes()
RETURNS TRIGGER AS $$
DECLARE
  immutable_status TEXT;
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT status INTO immutable_status
    FROM learner_pathway_versions
    WHERE tenant_id = NEW.tenant_id AND id = NEW.pathway_version_id;
  ELSE
    SELECT status INTO immutable_status
    FROM learner_pathway_versions
    WHERE tenant_id = OLD.tenant_id AND id = OLD.pathway_version_id;

    IF TG_OP = 'UPDATE' AND NEW.pathway_version_id IS DISTINCT FROM OLD.pathway_version_id THEN
      IF EXISTS (
        SELECT 1 FROM learner_pathway_versions
        WHERE tenant_id = NEW.tenant_id
          AND id = NEW.pathway_version_id
          AND status IN ('published', 'superseded')
      ) THEN
        RAISE EXCEPTION 'requirements on published pathway versions are immutable';
      END IF;
    END IF;
  END IF;

  IF immutable_status IN ('published', 'superseded') THEN
    RAISE EXCEPTION 'requirements on published pathway versions are immutable';
  END IF;
  RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_prevent_published_pathway_requirement_changes
  ON learner_pathway_requirements;
CREATE TRIGGER trg_prevent_published_pathway_requirement_changes
BEFORE INSERT OR UPDATE OR DELETE ON learner_pathway_requirements
FOR EACH ROW EXECUTE FUNCTION prevent_published_pathway_requirement_changes();

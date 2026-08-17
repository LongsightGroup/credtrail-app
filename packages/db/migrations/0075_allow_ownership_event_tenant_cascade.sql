-- Keep ownership events immutable while allowing parent-driven tenant cascades.

CREATE OR REPLACE FUNCTION trg_badge_template_ownership_events_immutable()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'DELETE'
    AND NOT EXISTS (
      SELECT 1
      FROM tenants
      WHERE id = OLD.tenant_id
    )
  THEN
    RETURN OLD;
  END IF;

  RAISE EXCEPTION 'badge_template_ownership_events is immutable';
END;
$$;

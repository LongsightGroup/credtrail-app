export const INSTITUTION_ADMIN_RULE_BUILDER_CSS = `
.ct-admin__builder-grid {
  --ct-grid-gap: 0.65rem;
}
.ct-admin__builder-grid.ct-grid {
  grid-template-columns: repeat(2, minmax(0, 1fr));
}
.ct-admin__builder-field-span {
  grid-column: 1 / -1;
}
.ct-admin-content--rule-builder {
  max-width: none;
}
.ct-admin-page-header--compact {
  max-width: 76rem;
}
.ct-admin__builder-shell {
  --ct-grid-gap: var(--ct-space-5);
  --ct-stack-gap: var(--ct-space-5);
  width: 100%;
  max-width: none;
}
.ct-admin__builder-shell.ct-grid {
  grid-template-columns: minmax(0, 1fr);
  align-items: start;
}
.ct-admin__builder-shell > * {
  min-width: 0;
}
.ct-admin__builder-shell.ct-grid .ct-admin__builder-support {
  grid-column: 1 / -1;
}
.ct-admin__builder-shell.ct-stack {
  --ct-stack-gap: var(--ct-space-4);
}
.ct-admin__builder-workbench-panel {
  min-width: 0;
  width: 100%;
  --ct-stack-gap: var(--ct-space-4);
}
.ct-admin__builder-workflow-head {
  display: grid;
  gap: 0.3rem;
}
.ct-admin__builder-steps-title {
  margin: 0;
  font-family: var(--ct-font-sans);
  font-size: 0.98rem;
  font-weight: 700;
  color: var(--ct-theme-text-title);
}
.ct-admin__builder-step {
  --ct-stack-gap: var(--ct-space-4);
  display: grid;
  gap: var(--ct-stack-gap);
  min-width: 0;
}
.ct-admin__pattern-panel + .ct-admin__builder-section {
  padding-top: var(--ct-space-3);
  border-top: 1px solid var(--ct-border-soft);
}
.ct-admin__step-panel.ct-admin__pattern-panel {
  --ct-stack-gap: 0.75rem;
}
.ct-admin__step-panel.ct-admin__pattern-panel h3 {
  margin: 0;
  font-size: 0.98rem;
}
.ct-admin__step-panel-lead {
  margin: 0;
  max-width: 65ch;
  font-size: 0.86rem;
  color: var(--ct-theme-text-muted);
}
.ct-admin__pattern-panel h4,
.ct-admin__pattern-panel p {
  margin: 0;
}
.ct-admin__builder-empty-state {
  --ct-stack-gap: 0.55rem;
  align-items: start;
  padding: 0.85rem 0.9rem;
  border-radius: var(--ct-radius-md);
  border: 1px dashed var(--ct-theme-border-info);
  background: var(--ct-theme-surface-info);
}
.ct-admin__builder-empty-state__title {
  margin: 0;
  font-size: 0.92rem;
  font-weight: 700;
  color: var(--ct-color-ink);
}
.ct-admin__builder-empty-state__body {
  margin: 0;
  max-width: 42ch;
  font-size: 0.86rem;
  line-height: 1.45;
  color: var(--ct-theme-text-muted);
}
.ct-admin__builder-step-callout[data-tone='warning'] {
  color: var(--ct-theme-state-warning);
  font-weight: 600;
}
.ct-admin__builder-section {
  --ct-stack-gap: 0.75rem;
}
.ct-admin__builder-section-head h4 {
  margin: 0;
  font-size: 0.96rem;
}
.ct-admin__builder-section-head p {
  margin: 0;
  max-width: 65ch;
  font-size: 0.86rem;
  color: var(--ct-theme-text-muted);
}
.ct-admin__builder-progress {
  margin: 0;
  font-size: 0.82rem;
  font-weight: 600;
  line-height: 1.4;
  color: var(--ct-theme-text-muted);
}
.ct-admin__builder-steps--vertical-stepper {
  display: grid;
  gap: 0;
}
.ct-admin__stepper-step {
  position: relative;
  display: flex;
  flex-direction: column;
  align-items: stretch;
  gap: 0.7rem;
  padding: 0 0 1.35rem 0.1rem;
  --ct-stepper-icon-center: 0.85rem;
}
.ct-admin__stepper-step:not(:last-child)::before {
  content: '';
  position: absolute;
  top: 2.35rem;
  bottom: 0;
  left: var(--ct-stepper-icon-center);
  width: 2px;
  transform: translateX(-50%);
  background: var(--ct-border-soft);
}
.ct-admin__stepper-header {
  position: relative;
  z-index: 1;
  min-width: 0;
}
.ct-admin__stepper-content {
  min-width: 0;
  padding-left: 2.65rem;
}
.ct-admin__stepper-step:not(.is-active) .ct-admin__stepper-content {
  display: none;
}
.ct-admin__builder-steps--vertical-stepper .ct-admin__step-button {
  width: fit-content;
  max-width: 100%;
  align-items: center;
  min-height: auto;
  padding: 0.2rem 0.45rem 0.2rem 0;
  border: none;
  border-radius: var(--ct-radius-sm);
  background: transparent;
  box-shadow: none;
}
.ct-admin__builder-steps--vertical-stepper .ct-admin__step-button:hover {
  color: var(--ct-theme-text-title);
  background: var(--ct-theme-surface-soft);
  transform: none;
  filter: none;
  box-shadow: none;
}
.ct-admin__builder-steps--vertical-stepper .ct-admin__step-button:hover .ct-admin__step-copy strong {
  color: var(--ct-theme-text-title);
}
.ct-admin__builder-steps--vertical-stepper .ct-admin__step-button:hover .ct-admin__step-copy small {
  color: var(--ct-theme-text-muted);
}
.ct-admin__builder-steps--vertical-stepper .ct-admin__step-copy small {
  display: block;
}
.ct-admin__stepper-step:not(.is-active) .ct-admin__step-copy small {
  color: var(--ct-theme-text-muted);
}
.ct-admin__builder-steps--vertical-stepper .ct-admin__step-button.is-active {
  color: var(--ct-theme-text-title);
  background: transparent;
  box-shadow: none;
}
.ct-admin__builder-steps--vertical-stepper .ct-admin__step-button.is-active .ct-admin__step-number {
  border-color: transparent;
  background: var(--ct-theme-gradient-action);
  color: var(--ct-theme-text-on-brand);
  box-shadow: var(--ct-shadow-soft);
}
.ct-admin__builder-steps--vertical-stepper .ct-admin__step-button.is-active .ct-admin__step-copy small {
  color: var(--ct-theme-text-muted);
}
.ct-admin__builder-steps--vertical-stepper .ct-admin__step-button.is-done {
  border: none;
  background: transparent;
  color: var(--ct-theme-text-body);
}
.ct-admin__builder-steps--vertical-stepper .ct-admin__step-button.is-done .ct-admin__step-number {
  border-color: var(--ct-theme-border-success);
  background: var(--ct-theme-surface-success);
  color: var(--ct-theme-state-success);
}
.ct-admin__builder-steps--vertical-stepper .ct-admin__step-button.is-active:hover {
  color: var(--ct-theme-text-title);
  background: var(--ct-theme-surface-soft);
  transform: none;
  filter: none;
  box-shadow: none;
}
.ct-admin__builder-steps--vertical-stepper .ct-admin__step-button.is-locked:hover,
.ct-admin__builder-steps--vertical-stepper .ct-admin__step-button:disabled:hover {
  border: none;
  background: transparent;
  color: var(--ct-theme-text-body);
  transform: none;
  filter: none;
  box-shadow: none;
}
.ct-admin__builder-workbench-panel {
  --ct-stack-gap: var(--ct-space-4);
}
.ct-admin__builder-step-footer {
  display: flex;
  flex-direction: column;
  gap: 0.65rem;
  align-items: flex-start;
  padding-top: 0.1rem;
}
.ct-admin__builder-step-footer > .ct-admin__status {
  width: 100%;
}
.ct-admin__builder-draft-actions.ct-cluster {
  --ct-cluster-gap: 0.55rem;
  justify-content: flex-start;
}
.ct-admin__builder-clone {
  --ct-stack-gap: 0.45rem;
  padding: 0.75rem 0.82rem;
  border: 1px dashed var(--ct-border-soft);
  border-radius: var(--ct-radius-md);
  background: var(--ct-theme-surface-soft);
}
.ct-admin__builder-clone summary {
  cursor: pointer;
  margin: 0;
  color: var(--ct-theme-text-title);
  font-size: 0.92rem;
  font-weight: 700;
}
.ct-admin__builder-clone select {
  flex: 1 1 24rem;
}
.ct-admin__builder-prereq {
  display: flex;
  flex-wrap: wrap;
  gap: var(--ct-space-2);
  align-items: center;
  color: var(--ct-theme-text-muted);
  font-size: 0.86rem;
  line-height: 1.4;
}
.ct-admin__builder-lms-status {
  display: flex;
  flex-wrap: wrap;
  gap: var(--ct-space-2);
  align-items: flex-start;
  margin: 0;
  padding: var(--ct-space-3);
  border: 1px solid var(--ct-theme-state-danger);
  border-radius: var(--ct-radius-md);
  background: var(--ct-theme-surface-danger);
  color: var(--ct-theme-state-danger);
  font-size: 0.9rem;
  font-weight: 650;
  line-height: 1.45;
}
.ct-admin__builder-lms-status[hidden] {
  display: none;
}
.ct-admin__builder-lms-status .ct-admin__text-action {
  color: var(--ct-theme-state-danger);
}
.ct-admin__builder-test-result {
  margin-top: 0.35rem;
}
.ct-admin__builder-step-callout {
  margin: 0;
  font-size: 0.88rem;
  line-height: 1.45;
  color: var(--ct-theme-text-muted);
}
.ct-admin__builder-workbench-panel .ct-admin__builder-step-nav {
  --ct-cluster-gap: 0.55rem;
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: flex-start;
}
.ct-admin__builder-workbench-panel .ct-admin__builder-step-nav #rule-builder-submit[hidden],
.ct-admin__builder-workbench-panel .ct-admin__builder-step-nav #rule-builder-step-next[hidden] {
  display: none;
}
.ct-admin__builder-intro-grid.ct-grid {
  --ct-grid-gap: 0.7rem;
  grid-template-columns: repeat(3, minmax(0, 1fr));
}
.ct-admin__builder-intro-card {
  --ct-stack-gap: 0.35rem;
  padding: 0.8rem 0.82rem;
  border-radius: var(--ct-radius-md);
  border: 1px solid var(--ct-border-soft);
  background: var(--ct-theme-surface-soft);
}
.ct-admin__builder-support {
  --ct-stack-gap: 0.85rem;
}
.ct-admin__builder-support-grid.ct-grid {
  --ct-grid-gap: 1rem;
  grid-template-columns: repeat(auto-fit, minmax(18rem, 1fr));
  align-items: start;
}
.ct-admin__builder-support-section {
  --ct-stack-gap: 0.55rem;
  min-width: 0;
}
.ct-admin__builder-support-section--wide {
  grid-column: 1 / -1;
}
.ct-admin__builder-support-section h3,
.ct-admin__builder-support-section h4 {
  margin: 0;
}
.ct-admin__builder-support-section h3 {
  font-size: 0.98rem;
}
.ct-admin__builder-support-section h4 {
  font-size: 0.92rem;
}
.ct-admin__pattern-panel {
  --ct-stack-gap: 0.7rem;
  padding: 0.82rem;
  border-radius: var(--ct-radius-md);
  border: 1px solid var(--ct-theme-border-info);
  background: var(--ct-theme-surface-info);
}
.ct-admin__pattern-panel h4,
.ct-admin__pattern-panel p {
  margin: 0;
}
.ct-admin__pattern-panel h4 {
  font-size: 0.98rem;
}
.ct-admin__pattern-panel p {
  max-width: 65ch;
  font-size: 0.86rem;
  color: var(--ct-theme-text-muted);
}
.ct-admin__builder-inline {
  --ct-cluster-gap: 0.5rem;
  align-items: end;
}
.ct-admin__builder-progress {
  margin-top: -0.15rem;
  font-size: 0.85rem;
  font-weight: 700;
}
.ct-admin__builder-workbench.ct-grid {
  --ct-grid-gap: 0.8rem;
  grid-template-columns: minmax(0, 1fr);
  align-items: start;
}
.ct-admin__builder-workbench.ct-stack {
  --ct-stack-gap: 0.8rem;
}
.ct-admin__builder-workbench-main {
  min-width: 0;
}
.ct-admin__builder-patterns {
  --ct-stack-gap: 0.6rem;
  padding: 0.75rem;
  border-radius: var(--ct-radius-md);
  border: 1px solid var(--ct-border-soft);
  background: linear-gradient(
    180deg,
    var(--ct-theme-surface-card-strong),
    var(--ct-theme-surface-soft)
  );
}
.ct-admin__builder-patterns-head {
  --ct-stack-gap: 0.28rem;
}
.ct-admin__step-head {
  --ct-stack-gap: 0.28rem;
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-md);
  background: linear-gradient(
    180deg,
    var(--ct-theme-surface-card-strong),
    var(--ct-theme-surface-soft)
  );
  padding: 0.62rem 0.66rem;
}
.ct-admin__step-head h3 {
  margin: 0;
  font-size: 0.98rem;
}
.ct-admin__step-head p {
  margin: 0;
  font-size: 0.87rem;
  color: var(--ct-theme-text-muted);
}
.ct-admin__builder-toolbar {
  --ct-cluster-gap: 0.45rem;
}
.ct-admin__builder-principle {
  --ct-stack-gap: 0.22rem;
  padding: 0.68rem 0.72rem;
  border-radius: var(--ct-radius-md);
  border: 1px solid var(--ct-theme-border-info);
  background: var(--ct-theme-surface-info);
}
.ct-admin__builder-principle strong,
.ct-admin__builder-principle p {
  margin: 0;
}
.ct-admin__builder-principle strong {
  color: var(--ct-color-ink);
  font-size: 0.9rem;
}
.ct-admin__builder-principle p {
  max-width: 70ch;
  color: var(--ct-theme-text-muted);
  font-size: 0.84rem;
}
.ct-admin__inline-control {
  display: grid;
  gap: 0.25rem;
  min-width: 12rem;
}
.ct-admin__field-label {
  font-size: 0.88rem;
  color: var(--ct-color-ink);
}
.ct-admin__segmented-control {
  display: inline-grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0.18rem;
  padding: 0.18rem;
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-sm);
  background: var(--ct-theme-surface-soft);
}
.ct-admin__segmented-control label {
  display: block;
  min-width: 0;
  cursor: pointer;
}
.ct-admin__segmented-control input {
  position: absolute;
  inline-size: 1px;
  block-size: 1px;
  width: 1px;
  height: 1px;
  margin: -1px;
  overflow: hidden;
  clip: rect(0 0 0 0);
  white-space: nowrap;
  border: 0;
}
.ct-admin__segmented-control span {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 2rem;
  padding: 0.36rem 0.58rem;
  border-radius: calc(var(--ct-radius-sm) - 2px);
  color: var(--ct-theme-text-muted);
  font-size: 0.82rem;
  font-weight: 700;
  line-height: 1.2;
  text-align: center;
  transition:
    background-color 160ms ease,
    color 160ms ease,
    box-shadow 160ms ease;
}
.ct-admin__segmented-control input:checked + span {
  background: var(--ct-theme-surface-card-strong);
  color: var(--ct-color-ink);
  box-shadow: var(--ct-shadow-soft);
}
.ct-admin__segmented-control input:focus-visible + span {
  outline: 2px solid var(--ct-theme-border-focus);
  outline-offset: 2px;
}
.ct-admin__builder-canvas {
  --ct-stack-gap: 0.55rem;
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-md);
  background: var(--ct-theme-surface-info);
  padding: 0.58rem;
}
.ct-admin__builder-canvas-header {
  justify-content: space-between;
}
.ct-admin__builder-canvas-meta {
  --ct-cluster-gap: 0.35rem;
}
.ct-admin__builder-canvas-empty {
  margin: 0;
  padding: 0.62rem 0.66rem;
  border-radius: var(--ct-radius-sm);
  border: 1px dashed var(--ct-border-soft);
  background: var(--ct-theme-surface-card-strong);
  color: var(--ct-theme-text-subtle);
  font-size: 0.84rem;
}
.ct-admin__builder-condition-list {
  --ct-stack-gap: 0.55rem;
}
.ct-admin__builder-flow {
  --ct-stack-gap: 0.58rem;
  padding: 0.72rem;
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-md);
  background: var(--ct-theme-surface-card-strong);
}
.ct-admin__builder-flow-list {
  display: grid;
  gap: 0.5rem;
  margin: 0;
  padding: 0;
  list-style: none;
}
.ct-admin__builder-flow-item {
  display: grid;
  grid-template-columns: minmax(3rem, 4rem) minmax(0, 1fr);
  gap: 0.48rem;
  align-items: stretch;
}
.ct-admin__builder-flow-item:first-child {
  grid-template-columns: minmax(0, 1fr);
}
.ct-admin__builder-flow-connector {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  align-self: center;
  min-height: 1.8rem;
  padding: 0.16rem 0.48rem;
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-pill);
  background: var(--ct-theme-surface-soft);
  color: var(--ct-theme-text-muted);
  font-size: 0.72rem;
  font-weight: 800;
  letter-spacing: 0;
}
.ct-admin__builder-flow-node {
  display: grid;
  gap: 0.12rem;
  min-width: 0;
  padding: 0.56rem 0.62rem;
  border: 1px solid var(--ct-theme-border-info);
  border-radius: var(--ct-radius-sm);
  background: var(--ct-theme-surface-info);
}
.ct-admin__builder-flow-node strong {
  color: var(--ct-color-ink);
  font-size: 0.88rem;
  line-height: 1.25;
}
.ct-admin__builder-flow-node p {
  margin: 0;
  color: var(--ct-theme-text-muted);
  font-size: 0.78rem;
  line-height: 1.35;
  overflow-wrap: anywhere;
}
.ct-admin__builder-flow-kicker {
  color: var(--ct-theme-text-subtle);
  font-size: 0.68rem;
  font-weight: 800;
  letter-spacing: 0;
  text-transform: uppercase;
}
.ct-admin__builder-flow-item--course_completion .ct-admin__builder-flow-node,
.ct-admin__builder-flow-item--issue .ct-admin__builder-flow-node {
  border-color: var(--ct-theme-border-success);
  background: var(--ct-theme-surface-success);
}
.ct-admin__builder-flow-item--grade_threshold .ct-admin__builder-flow-node,
.ct-admin__builder-flow-item--custom_field .ct-admin__builder-flow-node {
  border-color: var(--ct-theme-border-focus);
  background: var(--ct-theme-surface-card-strong);
}
.ct-admin__builder-flow-item--assignment_submission .ct-admin__builder-flow-node,
.ct-admin__builder-flow-item--time_window .ct-admin__builder-flow-node {
  border-color: var(--ct-theme-border-warning);
  background: var(--ct-theme-surface-warning);
}
.ct-admin__builder-flow-item--prerequisite_badge .ct-admin__builder-flow-node {
  border-color: var(--ct-theme-border-danger);
  background: var(--ct-theme-surface-danger);
}
.ct-admin__builder-test-layout.ct-grid,
.ct-admin__builder-review-layout.ct-grid {
  --ct-grid-gap: 0.8rem;
  grid-template-columns: minmax(0, 1fr);
  align-items: start;
}
.ct-admin__builder-test-actions {
  display: flex;
  justify-content: flex-start;
}
.ct-admin__builder-governance {
  --ct-stack-gap: 0.75rem;
  margin-top: 0.9rem;
}
.ct-admin__builder-simulation {
  padding: 0.82rem;
  border-radius: var(--ct-radius-md);
  border: 1px solid var(--ct-border-soft);
  background: linear-gradient(
    180deg,
    var(--ct-theme-surface-card-strong),
    var(--ct-theme-surface-soft)
  );
}
.ct-admin__builder-test-rail,
.ct-admin__builder-checklist-panel,
.ct-admin__builder-rail-card {
  padding: 0.78rem 0.82rem;
  border-radius: var(--ct-radius-md);
  border: 1px solid var(--ct-border-soft);
  background: var(--ct-theme-surface-soft);
}
.ct-admin__builder-source-panel {
  --ct-stack-gap: 0.56rem;
  padding-top: 0.74rem;
  border-top: 1px solid var(--ct-border-soft);
}
.ct-admin__builder-source-list {
  display: grid;
  gap: 0.46rem;
  margin: 0;
  padding: 0;
}
.ct-admin__builder-source-list > div {
  display: grid;
  gap: 0.18rem;
  padding: 0.54rem 0.58rem;
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-sm);
  background: var(--ct-theme-surface-card-strong);
}
.ct-admin__builder-source-list dt {
  color: var(--ct-color-ink);
  font-size: 0.82rem;
  font-weight: 700;
}
.ct-admin__builder-source-list dd {
  display: flex;
  flex-wrap: wrap;
  gap: 0.36rem;
  align-items: center;
  margin: 0;
  color: var(--ct-theme-text-muted);
  font-size: 0.78rem;
  line-height: 1.35;
}
.ct-admin__builder-rail-card > summary,
.ct-admin__builder-simulation > summary {
  display: flex;
  align-items: center;
  min-height: 2.4rem;
  cursor: pointer;
  font-weight: 700;
  color: var(--ct-color-ink);
}
.ct-admin__builder-summary-list {
  grid-template-columns: repeat(5, minmax(0, 1fr));
}
.ct-admin__builder-checklist {
  margin: 0;
  padding: 0 0 0 1rem;
  display: grid;
  gap: 0.34rem;
  color: var(--ct-theme-text-body);
}
.ct-admin__builder-checklist li {
  line-height: 1.35;
}
.ct-admin__condition-card {
  --ct-stack-gap: 0.5rem;
  border: 1px solid var(--ct-theme-border-info);
  border-radius: var(--ct-radius-md);
  background: var(--ct-theme-surface-card-strong);
  padding: 0.82rem;
}
.ct-admin__condition-card.is-dragging {
  opacity: 0.65;
  box-shadow: var(--ct-focus-ring);
}
.ct-admin__condition-card--course_completion {
  border-color: var(--ct-theme-border-success);
}
.ct-admin__condition-card--grade_threshold {
  border-color: var(--ct-theme-border-focus);
}
.ct-admin__condition-card--program_completion {
  border-color: var(--ct-theme-border-info);
}
.ct-admin__condition-card--assignment_submission {
  border-color: var(--ct-theme-border-warning);
}
.ct-admin__condition-card--survey_completion {
  border-color: var(--ct-theme-border-info);
}
.ct-admin__condition-card--time_window {
  border-color: var(--ct-border-strong);
}
.ct-admin__condition-card--prerequisite_badge {
  border-color: var(--ct-theme-border-danger);
}
.ct-admin__condition-card--custom_field {
  border-color: var(--ct-theme-border-focus);
}
.ct-admin__condition-card--result-idle {
  box-shadow: none;
}
.ct-admin__condition-card--result-pass {
  border-color: var(--ct-theme-border-success);
  background: var(--ct-theme-surface-success);
}
.ct-admin__condition-card--result-fail {
  border-color: var(--ct-theme-border-danger);
  background: var(--ct-theme-surface-danger);
}
.ct-admin__condition-card--result-review {
  border-color: var(--ct-theme-border-warning);
  background: var(--ct-theme-surface-warning);
}
.ct-admin__condition-header {
  --ct-cluster-gap: 0.5rem;
  align-items: stretch;
}
.ct-admin__condition-header-row {
  --ct-cluster-gap: 0.42rem;
  justify-content: space-between;
  align-items: center;
}
.ct-admin__condition-summary {
  margin: 0;
  font-size: 0.92rem;
  line-height: 1.45;
  font-weight: 600;
  color: var(--ct-color-ink);
}
.ct-admin__condition-details {
  --ct-stack-gap: 0.55rem;
}
.ct-admin__condition-details > summary {
  cursor: pointer;
  font-size: 0.82rem;
  font-weight: 600;
  color: var(--ct-theme-text-muted);
}
.ct-admin__condition-index {
  display: inline-flex;
  align-items: center;
  border-radius: var(--ct-radius-pill);
  border: 1px solid var(--ct-border-soft);
  background: var(--ct-theme-surface-soft);
  color: var(--ct-theme-text-muted);
  font-size: 0.74rem;
  font-weight: 700;
  letter-spacing: 0.03em;
  padding: 0.16rem 0.48rem;
}
.ct-admin__condition-drag {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: auto;
  height: 1.7rem;
  border-radius: var(--ct-radius-sm);
  border: 1px solid var(--ct-border-soft);
  background: var(--ct-theme-surface-info);
  color: var(--ct-theme-text-muted);
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0;
  padding: 0 0.42rem;
  cursor: grab;
  user-select: none;
}
.ct-admin__actions.ct-admin__condition-actions {
  gap: 0.36rem;
}
.ct-admin__condition-header-fields.ct-grid {
  --ct-grid-gap: var(--ct-space-3);
  grid-template-columns: minmax(0, 1fr) minmax(10rem, auto);
  align-items: end;
}
.ct-admin__condition-header-fields label {
  min-width: 0;
}
.ct-admin__condition-advanced {
  align-self: end;
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-sm);
  background: var(--ct-theme-surface-soft);
  padding: 0.22rem 0.42rem;
}
.ct-admin__condition-advanced > summary {
  cursor: pointer;
  color: var(--ct-theme-text-muted);
  font-size: 0.78rem;
  font-weight: 700;
}
.ct-admin__condition-advanced[open] > summary {
  margin-bottom: 0.36rem;
}
.ct-admin__condition-fields.ct-grid {
  --ct-grid-gap: var(--ct-space-3);
  grid-template-columns: repeat(2, minmax(0, 1fr));
}
.ct-admin__condition-field {
  min-width: 0;
}
.ct-admin__condition-help {
  margin: 0;
  font-size: 0.79rem;
  color: var(--ct-theme-text-subtle);
}
.ct-admin__condition-result {
  margin: 0;
  font-size: 0.78rem;
  font-weight: 700;
}
.ct-admin__condition-result[data-state='idle'] {
  color: var(--ct-theme-text-subtle);
}
.ct-admin__condition-result[data-state='pass'] {
  color: var(--ct-theme-state-success);
}
.ct-admin__condition-result[data-state='fail'] {
  color: var(--ct-theme-state-danger);
}
.ct-admin__condition-result[data-state='review'] {
  color: var(--ct-theme-state-warning);
}

.ct-admin__builder-step[hidden] {
  display: none;
}
.ct-admin__builder-step-nav {
  --ct-cluster-gap: 0.55rem;
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: flex-start;
}
.ct-admin__builder-step-nav #rule-builder-submit[hidden],
.ct-admin__builder-step-nav #rule-builder-step-next[hidden] {
  display: none;
}
.ct-admin__step-button.is-current-only {
  cursor: default;
}
.ct-admin__step-button.is-current-only:hover {
  background: transparent;
}
.ct-admin__builder-steps--vertical-stepper .ct-admin__step-button.is-current-only:hover {
  background: transparent;
}
.ct-admin__builder-steps {
  list-style: none;
  margin: 0;
  padding: 0;
  display: grid;
  gap: 0.48rem;
}
.ct-admin__step-button {
  width: 100%;
  display: grid;
  box-sizing: border-box;
  appearance: none;
  grid-template-columns: auto minmax(0, 1fr);
  align-items: start;
  gap: 0.65rem;
  text-align: left;
  border: 1px solid var(--ct-border-strong);
  border-radius: var(--ct-radius-md);
  background: var(--ct-theme-surface-info);
  color: var(--ct-theme-text-body);
  min-height: 2.75rem;
  font-family: var(--ct-font-sans);
  font-size: 0.82rem;
  font-weight: 700;
  line-height: 1.2;
  padding: 0.7rem 0.8rem;
  cursor: pointer;
  transition:
    border-color var(--ct-duration-fast) var(--ct-ease-standard),
    background var(--ct-duration-fast) var(--ct-ease-standard),
    color var(--ct-duration-fast) var(--ct-ease-standard),
    box-shadow var(--ct-duration-fast) var(--ct-ease-standard);
}
.ct-admin__step-number {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  inline-size: 1.7rem;
  block-size: 1.7rem;
  border-radius: 999px;
  border: 1px solid var(--ct-border-soft);
  background: var(--ct-theme-surface-card-strong);
  color: var(--ct-theme-text-subtle);
  font-size: 0.78rem;
}
.ct-admin__step-copy {
  display: grid;
  gap: 0.16rem;
}
.ct-admin__step-copy strong {
  font-size: 0.84rem;
}
.ct-admin__step-copy small {
  font-size: 0.75rem;
  font-weight: 500;
  line-height: 1.35;
  color: var(--ct-theme-text-muted);
}
.ct-admin__step-button:hover {
  border-color: var(--ct-theme-border-focus);
}
.ct-admin__step-button.is-done {
  border-color: var(--ct-theme-border-success);
  background: var(--ct-theme-surface-success);
  color: var(--ct-theme-state-success);
}
.ct-admin__step-button.is-done .ct-admin__step-number {
  border-color: var(--ct-theme-border-success);
  background: var(--ct-theme-surface-card-strong);
  color: var(--ct-theme-state-success);
}
.ct-admin__step-button.is-done .ct-admin__step-copy strong::after {
  content: ' \u2713';
  font-weight: 800;
}
.ct-admin__step-button.is-active {
  color: var(--ct-theme-text-on-brand);
  border-color: transparent;
  background: var(--ct-theme-gradient-action);
  box-shadow: var(--ct-shadow-soft);
}
.ct-admin__step-button.is-active .ct-admin__step-number {
  border-color: rgba(255, 255, 255, 0.28);
  background: rgba(255, 255, 255, 0.18);
  color: var(--ct-theme-text-on-brand);
}
.ct-admin__step-button.is-active .ct-admin__step-copy small {
  color: rgba(255, 255, 255, 0.78);
}
.ct-admin__step-button.is-locked,
.ct-admin__step-button:disabled {
  opacity: 0.58;
  cursor: not-allowed;
  box-shadow: none;
}
.ct-admin__step-button.is-locked:hover,
.ct-admin__step-button:disabled:hover {
  border-color: var(--ct-border-strong);
  background: var(--ct-theme-surface-info);
  color: var(--ct-theme-text-body);
}
.ct-admin__builder-steps--vertical-stepper .ct-admin__step-button.is-locked,
.ct-admin__builder-steps--vertical-stepper .ct-admin__step-button:disabled {
  opacity: 1;
  color: var(--ct-theme-text-body);
}
.ct-admin__builder-steps--vertical-stepper .ct-admin__step-button.is-locked .ct-admin__step-number,
.ct-admin__builder-steps--vertical-stepper .ct-admin__step-button:disabled .ct-admin__step-number {
  border-color: var(--ct-border-soft);
  background: var(--ct-theme-surface-soft);
  color: var(--ct-theme-text-muted);
}
.ct-admin__builder-steps--vertical-stepper .ct-admin__step-button.is-locked .ct-admin__step-copy strong,
.ct-admin__builder-steps--vertical-stepper .ct-admin__step-button:disabled .ct-admin__step-copy strong {
  color: var(--ct-theme-text-title);
}
.ct-admin__builder-steps--vertical-stepper .ct-admin__step-button.is-locked .ct-admin__step-copy small,
.ct-admin__builder-steps--vertical-stepper .ct-admin__step-button:disabled .ct-admin__step-copy small {
  color: var(--ct-theme-text-muted);
}
.ct-admin__builder-advanced {
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-md);
  background: var(--ct-theme-surface-soft);
  padding: 0.58rem 0.64rem;
}
.ct-admin__builder-advanced > summary {
  display: flex;
  align-items: center;
  min-height: 2.75rem;
  cursor: pointer;
  font-weight: 700;
  color: var(--ct-color-ink);
}
.ct-admin__builder-advanced[open] > summary {
  margin-bottom: 0.45rem;
}
.ct-admin__builder-advanced--inline {
  min-width: min(100%, 22rem);
  padding-block: 0.36rem;
}
.ct-admin__builder-advanced--inline > summary {
  min-height: 2.15rem;
}
.ct-admin__builder-guide {
  border: 1px solid var(--ct-border-soft);
  border-radius: var(--ct-radius-md);
  background: var(--ct-theme-surface-soft);
  padding: 0.58rem 0.64rem;
}
.ct-admin__builder-guide > summary {
  display: flex;
  align-items: center;
  min-height: 2.75rem;
  cursor: pointer;
  font-weight: 700;
  color: var(--ct-color-ink);
}
.ct-admin__builder-guide[open] > summary {
  margin-bottom: 0.45rem;
}
.ct-admin__builder-guide-list {
  margin: 0;
  padding: 0;
  display: grid;
  gap: 0.45rem;
}
.ct-admin__builder-guide-list > div {
  display: grid;
  gap: 0.1rem;
}
.ct-admin__builder-guide-list dt {
  font-size: 0.82rem;
  font-weight: 700;
  color: var(--ct-color-ink);
}
.ct-admin__builder-guide-list dd {
  margin: 0;
  font-size: 0.79rem;
  color: var(--ct-theme-text-muted);
}
.ct-admin__builder-summary-list {
  margin: 0;
  padding: 0;
  display: grid;
  gap: 0.48rem;
}
.ct-admin__builder-summary-list > div {
  display: grid;
  gap: 0.12rem;
}
.ct-admin__builder-summary-list dt {
  font-size: 0.8rem;
  color: var(--ct-color-ink-soft);
}
.ct-admin__builder-summary-list dd {
  margin: 0;
  color: var(--ct-color-ink);
  font-weight: 700;
}
.ct-admin__builder-summary-value[data-tone='success'] {
  color: var(--ct-theme-state-success);
}
.ct-admin__builder-summary-value[data-tone='warning'] {
  color: var(--ct-theme-state-warning);
}
.ct-admin__builder-summary-value[data-tone='error'] {
  color: var(--ct-theme-state-danger);
}

`;

export const INSTITUTION_ADMIN_RULE_BUILDER_RESPONSIVE_CSS = `
  .ct-admin__builder-grid.ct-grid,
  .ct-admin__condition-fields.ct-grid,
  .ct-admin__condition-header-fields.ct-grid,
  .ct-admin__builder-intro-grid.ct-grid,
  .ct-admin__builder-workbench.ct-grid,
  .ct-admin__builder-test-layout.ct-grid,
  .ct-admin__builder-review-layout.ct-grid {
    grid-template-columns: minmax(0, 1fr);
  }

  .ct-admin__builder-inline,
  .ct-admin__builder-toolbar,
  .ct-admin__builder-step-nav {
    flex-direction: column;
    align-items: stretch;
  }

  .ct-admin__builder-summary-list {
    grid-template-columns: minmax(0, 1fr);
  }

  .ct-admin__builder-flow-item,
  .ct-admin__builder-flow-item:first-child {
    grid-template-columns: minmax(0, 1fr);
  }

  .ct-admin__builder-flow-connector {
    justify-self: start;
  }
`;

const attentionControl = document.querySelector('[data-import-attention-control]');
if (attentionControl instanceof HTMLElement) attentionControl.hidden = false;
document.querySelector('[data-import-attention]')?.addEventListener('change', (event) => {
  if (!(event.target instanceof HTMLInputElement)) return;
  let visible = 0;
  for (const row of document.querySelectorAll('[data-import-preview-row]')) {
    if (!(row instanceof HTMLElement)) continue;
    row.hidden = event.target.checked && row.dataset.needsAttention !== 'true';
    if (!row.hidden) visible++;
  }
  const status = document.getElementById('import-preview-filter-status');
  if (status) status.textContent = `${visible} ${visible === 1 ? 'row' : 'rows'} shown.`;
});
let timer;
let loading = false;
let failures = 0;
const schedule = () => {
  clearTimeout(timer);
  if (!document.hidden && failures < 3 && document.getElementById('learner-import-progress')?.dataset.importActive === 'true')
    timer = setTimeout(refreshProgress, 10000 * (failures + 1));
};
const refreshProgress = async (manual = false) => {
  const panel = document.getElementById('learner-import-progress');
  if (!panel || loading || document.hidden) return;
  if (!manual && panel.contains(document.activeElement)) { schedule(); return; }
  loading = true;
  try {
    const response = await fetch(panel.dataset.progressUrl, { credentials: 'same-origin', cache: 'no-store', signal: AbortSignal.timeout(15000) });
    if (!response.ok || response.redirected) throw new Error('Progress unavailable');
    const parsed = new DOMParser().parseFromString(await response.text(), 'text/html');
    const next = parsed.getElementById('learner-import-progress');
    if (!next) throw new Error('Progress unavailable');
    panel.replaceWith(next);
    failures = 0;
    if (manual) next.querySelector('[data-refresh-imports]')?.focus({ preventScroll: true });
  } catch {
    failures++;
    const status = panel.querySelector('[data-import-refresh-status]');
    if (status) status.textContent = failures >= 3 ? 'Automatic refresh paused. Choose Refresh progress to try again.' : 'Progress could not be refreshed. Your import continues; checking again shortly.';
  } finally {
    loading = false;
    schedule();
  }
};
document.addEventListener('click', (event) => {
  if (!(event.target instanceof Element) || !event.target.closest('[data-refresh-imports]')) return;
  event.preventDefault(); failures = 0; void refreshProgress(true);
});
document.addEventListener('visibilitychange', schedule);
window.addEventListener('pagehide', () => clearTimeout(timer));
window.addEventListener('pageshow', schedule);
schedule();

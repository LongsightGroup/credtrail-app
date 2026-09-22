let refreshTimer;
let refreshing = false;
let failures = 0;
const currentActions = () => document.getElementById('home-action-items');
const setRefreshStatus = (panel, text) => {
  const status = panel?.querySelector('[data-home-refresh-status]');
  if (status) status.textContent = text;
};
const scheduleRefresh = () => {
  clearTimeout(refreshTimer);
  if (!document.hidden && failures < 3 && currentActions())
    refreshTimer = setTimeout(() => { void refreshActions(); }, 30000);
};
const refreshActions = async (manual = false) => {
  const panel = currentActions();
  if (!panel || refreshing || document.hidden) return;
  if (!manual && panel.contains(document.activeElement)) { scheduleRefresh(); return; }
  refreshing = true;
  try {
    const response = await fetch(location.pathname, { credentials: 'same-origin', cache: 'no-store', signal: AbortSignal.timeout(15000) });
    if (!response.ok || response.redirected) throw new Error('Actions unavailable');
    const next = new DOMParser().parseFromString(await response.text(), 'text/html').getElementById('home-action-items');
    if (!next) throw new Error('Actions unavailable');
    // Do not replace a link the user focused while this request was in flight.
    if (!manual && panel.contains(document.activeElement)) return;
    setRefreshStatus(next, 'Updated just now. Checks every 30 seconds.');
    panel.replaceWith(next);
    if (manual) next.querySelector('[data-refresh-home-actions]')?.focus({ preventScroll: true });
    failures = 0;
  } catch {
    failures++;
    setRefreshStatus(panel, failures >= 3 ? 'Automatic updates paused. Choose Refresh actions to try again.' : 'Could not update actions. Checking again shortly.');
  } finally {
    refreshing = false;
    scheduleRefresh();
  }
};
document.addEventListener('click', (event) => {
  if (!(event.target instanceof Element) || !event.target.closest('[data-refresh-home-actions]')) return;
  event.preventDefault(); failures = 0; void refreshActions(true);
});
document.addEventListener('visibilitychange', () => {
  if (document.hidden) clearTimeout(refreshTimer);
  else { failures = 0; void refreshActions(); }
});
window.addEventListener('pageshow', (event) => {
  if (event.persisted) { failures = 0; void refreshActions(); }
  else scheduleRefresh();
});
window.addEventListener('pagehide', () => clearTimeout(refreshTimer));
setRefreshStatus(currentActions(), 'Checks every 30 seconds and when you return to this tab.');
scheduleRefresh();

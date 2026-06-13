function switchTab(tab) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
  document.getElementById('tab-reset').classList.toggle('hidden', tab !== 'reset');
  document.getElementById('tab-portal').classList.toggle('hidden', tab !== 'portal');
}

function tabFromHash() {
  return location.hash === '#reset' ? 'reset' : 'portal';
}

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      location.hash = btn.dataset.tab;  // triggers hashchange → switchTab
    });
  });

  window.addEventListener('hashchange', () => switchTab(tabFromHash()));

  initSerial();
  initPortal();
  switchTab(tabFromHash());
});

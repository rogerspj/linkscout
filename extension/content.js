'use strict';

// Firefox uses browser.* instead of chrome.* for extension APIs.
// This one line makes chrome.* work in Firefox without a separate polyfill file.
if (typeof browser !== 'undefined') globalThis.chrome = browser;

// ─── What this file does ──────────────────────────────────────────────────────
// content.js is injected into every http/https page the user visits.
// It listens for messages from background.js and manages the popup DOM.
//
// It does NOT fetch the API directly — that lives in background.js.
// Reason: content scripts run in the page's browser context and are
// subject to CORS, which would block requests to our EC2 backend.
// The background service worker bypasses this restriction.

// ─── Configuration ────────────────────────────────────────────────────────────
const EC2_FRONTEND = 'http://18.144.144.119';

// Verdict display — same colors as the React frontend (App.jsx VERDICT_META)
const VERDICT_META = {
  dangerous:   { color: '#f85149', label: 'DANGEROUS' },
  disputed:    { color: '#e3833c', label: 'DISPUTED' },
  suspicious:  { color: '#d29922', label: 'SUSPICIOUS' },
  likely_safe: { color: '#3fb950', label: 'LIKELY SAFE' },
  unknown:     { color: '#8b949e', label: 'UNKNOWN' },
};

const AGE_COLORS = {
  very_new:       '#d29922',
  relatively_new: '#8b949e',
  established:    '#3fb950',
  unavailable:    '#8b949e',
};

// ─── State ────────────────────────────────────────────────────────────────────
// These are simple module-level variables — no framework needed.
let lastContextX   = 0;   // viewport X of the last right-click
let lastContextY   = 0;   // viewport Y of the last right-click
let currentCheckUrl = null; // URL being checked (needed for Retry and "See full details")

// ─── Track right-click position ───────────────────────────────────────────────
// We record this here because the background service worker's context menu
// handler does NOT receive cursor coordinates — only page/link URL info.
// We use capture:true so we catch the event even on elements that stop propagation.
document.addEventListener('contextmenu', e => {
  lastContextX = e.clientX;
  lastContextY = e.clientY;
}, true);

// ─── Message listener ─────────────────────────────────────────────────────────
// background.js sends one of three message types depending on fetch state.
chrome.runtime.onMessage.addListener(msg => {
  switch (msg.type) {
    case 'LINKSCOUT_SHOW_LOADING':
      currentCheckUrl = msg.url;
      upsertPopup();
      renderLoading();
      break;

    case 'LINKSCOUT_SHOW_RESULT':
      upsertPopup();
      renderResult(msg.data);
      break;

    case 'LINKSCOUT_SHOW_ERROR':
      upsertPopup();
      renderError();
      break;
  }
});

// ─── Popup lifecycle ──────────────────────────────────────────────────────────

function upsertPopup() {
  // If a popup is already open (from a previous check), reuse it in place
  // rather than creating a new one — avoids flicker on retry.
  if (document.getElementById('linkscout-popup')) return;

  const popup = document.createElement('div');
  popup.id = 'linkscout-popup';

  // Position near the right-click point, nudged 8px so the cursor
  // doesn't land on the popup edge. Clamp to keep it inside the viewport.
  const POPUP_W = 316;  // matches CSS width + border
  const POPUP_H = 210;  // generous estimate — better to clamp up than clip

  let x = lastContextX + 8;
  let y = lastContextY + 8;

  // Flip left if popup would overflow the right edge
  if (x + POPUP_W > window.innerWidth - 8) {
    x = Math.max(8, lastContextX - POPUP_W - 8);
  }
  // Flip up if popup would overflow the bottom edge
  if (y + POPUP_H > window.innerHeight - 8) {
    y = Math.max(8, lastContextY - POPUP_H - 8);
  }

  popup.style.left = x + 'px';
  popup.style.top  = y + 'px';

  document.body.appendChild(popup);

  // Dismiss on click outside or Escape.
  // Use setTimeout so the current click that opened the context menu
  // doesn't immediately close the popup.
  setTimeout(() => {
    document.addEventListener('click',   handleOutsideClick);
    document.addEventListener('keydown', handleEscape);
  }, 0);
}

function removePopup() {
  const popup = document.getElementById('linkscout-popup');
  if (popup) popup.remove();
  document.removeEventListener('click',   handleOutsideClick);
  document.removeEventListener('keydown', handleEscape);
}

function handleOutsideClick(e) {
  const popup = document.getElementById('linkscout-popup');
  if (popup && !popup.contains(e.target)) removePopup();
}

function handleEscape(e) {
  if (e.key === 'Escape') removePopup();
}

// ─── State renderers ──────────────────────────────────────────────────────────
// Each renderer replaces the popup's innerHTML for its state.
// All user-controlled strings go through escapeHtml() to prevent XSS.

function renderLoading() {
  setPopupHTML(`
    <div class="ls-header">
      <span class="ls-logo">🔍 LinkScout</span>
      <button class="ls-close">✕</button>
    </div>
    <div class="ls-body">
      <div class="ls-loading">
        <span class="ls-spinner"></span>Checking…
      </div>
    </div>
  `);
}

function renderResult(data) {
  const meta       = VERDICT_META[data.verdict] ?? VERDICT_META.unknown;
  const ageColor   = AGE_COLORS[data.domain_age_label] ?? '#8b949e';
  const ageText    = humanAge(data.domain_age_days);
  // Show only the first sentence of the age note to keep the popup compact
  const ageNote    = (data.domain_age_note ?? '').split('.')[0];
  const showAge    = data.domain_age_label && data.domain_age_label !== 'unavailable';

  // Truncate long explanations — the full text is one click away
  const explanation = data.explanation ?? '';
  const truncated   = explanation.length > 150
    ? explanation.slice(0, 147) + '…'
    : explanation;

  // Build the "See full details" URL. Validate that currentCheckUrl is safe
  // before embedding it in an href (links can have javascript: or data: schemes).
  const safeTarget  = isSafeUrl(currentCheckUrl) ? currentCheckUrl : '';
  const detailsHref = `${EC2_FRONTEND}/?url=${encodeURIComponent(safeTarget)}`;

  setPopupHTML(`
    <div class="ls-header">
      <span class="ls-logo">🔍 LinkScout</span>
      <button class="ls-close">✕</button>
    </div>
    <div class="ls-body">
      <div class="ls-verdict" style="--verdict-color:${meta.color}">${meta.label}</div>
      <p class="ls-explanation">${escapeHtml(truncated)}</p>
      ${showAge ? `
      <div class="ls-age">
        <span>📅</span>
        <span class="ls-age-value" style="color:${ageColor}">${escapeHtml(ageText)}</span>
        ${ageNote ? `<span class="ls-age-note">${escapeHtml(ageNote)}.</span>` : ''}
      </div>
      ` : ''}
    </div>
    <div class="ls-footer">
      <a class="ls-details-link" href="${detailsHref}" target="_blank" rel="noopener noreferrer">
        See full details →
      </a>
    </div>
  `);
}

function renderError() {
  setPopupHTML(`
    <div class="ls-header">
      <span class="ls-logo">🔍 LinkScout</span>
      <button class="ls-close">✕</button>
    </div>
    <div class="ls-body">
      <div class="ls-error">
        Couldn't reach the LinkScout backend.
        <button class="ls-retry">Retry</button>
      </div>
    </div>
  `);

  // Retry: tell background.js to try the same URL again
  const popup = document.getElementById('linkscout-popup');
  popup.querySelector('.ls-retry').addEventListener('click', () => {
    if (currentCheckUrl) {
      renderLoading();
      chrome.runtime.sendMessage({ type: 'LINKSCOUT_RETRY', url: currentCheckUrl });
    }
  });
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function setPopupHTML(html) {
  const popup = document.getElementById('linkscout-popup');
  if (!popup) return;
  popup.innerHTML = html;
  // Re-attach close button listener (innerHTML replacement removes old listeners)
  popup.querySelector('.ls-close')?.addEventListener('click', removePopup);
}

function humanAge(days) {
  if (days === null || days === undefined) return 'Unknown';
  if (days < 30) return `${days} day${days !== 1 ? 's' : ''}`;
  if (days < 365) {
    const m = Math.floor(days / 30);
    return `${m} month${m !== 1 ? 's' : ''}`;
  }
  const y = Math.floor(days / 365);
  return `${y} year${y !== 1 ? 's' : ''}`;
}

// Escape characters that have special meaning in HTML.
// Any user-controlled string injected into innerHTML must go through this.
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Only embed a URL in an href if it's http or https.
// This blocks javascript:, data:, and other potentially dangerous schemes.
function isSafeUrl(url) {
  try {
    const u = new URL(url);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch {
    return false;
  }
}

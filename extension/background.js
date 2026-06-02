'use strict';

// Firefox uses browser.* instead of chrome.* for extension APIs.
// This one line makes chrome.* work in Firefox without a separate polyfill file.
if (typeof browser !== 'undefined') globalThis.chrome = browser;

// ─── Configuration ────────────────────────────────────────────────────────────
// One constant to change if the backend moves.
const API_BASE = 'http://18.144.144.119';

// ─── Context menu setup ───────────────────────────────────────────────────────
// onInstalled fires when the extension is first installed or reloaded.
// We create the menu item here rather than at the top level because
// service workers can be terminated and restarted by Chrome at any time.
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'linkscout-check',
    title: 'Check with LinkScout',
    // contexts: ['link'] means the item only appears when the user
    // right-clicks a hyperlink — not on images, text, or the page background.
    contexts: ['link'],
  });
});

// ─── Context menu click ───────────────────────────────────────────────────────
// info.linkUrl is the href of the link that was right-clicked.
// tab is the Tab object for the page the user is on.
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== 'linkscout-check') return;

  const url = info.linkUrl;

  // Only check http/https links. Skip javascript:, mailto:, data:, etc.
  if (!url || !/^https?:\/\//i.test(url)) return;
  if (!tab?.id) return;

  // Show the loading popup in the page immediately so the user gets
  // instant feedback while the API call is in flight.
  try {
    await chrome.tabs.sendMessage(tab.id, { type: 'LINKSCOUT_SHOW_LOADING', url });
  } catch {
    // Content script not loaded on this page (e.g., chrome:// pages,
    // extension pages, or pages loaded before the extension was installed).
    // Nothing to do — fail silently.
    return;
  }

  await fetchAndSend(url, tab.id);
});

// ─── Retry request from content.js ───────────────────────────────────────────
// When the user clicks "Retry" in the error state, content.js sends this message.
// sender.tab.id tells us which tab to respond to.
chrome.runtime.onMessage.addListener((msg, sender) => {
  if (msg.type === 'LINKSCOUT_RETRY' && msg.url && sender.tab?.id) {
    chrome.tabs.sendMessage(sender.tab.id, { type: 'LINKSCOUT_SHOW_LOADING', url: msg.url })
      .then(() => fetchAndSend(msg.url, sender.tab.id))
      .catch(() => {}); // tab may have navigated away
  }
});

// ─── API fetch ────────────────────────────────────────────────────────────────
// Runs in the background context (service worker in Chrome, background page in Firefox).
// Both browsers bypass CORS for fetch requests to URLs listed in host_permissions —
// Chrome because service workers aren't subject to the Same-Origin Policy,
// Firefox because it grants cross-origin access to host_permissions URLs even in
// page contexts. The "*://18.144.144.119/*" pattern in manifest.json covers this.
async function fetchAndSend(url, tabId) {
  try {
    const response = await fetch(`${API_BASE}/api/check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    chrome.tabs.sendMessage(tabId, { type: 'LINKSCOUT_SHOW_RESULT', data });
  } catch (err) {
    console.error('LinkScout: API fetch failed:', err.message);
    chrome.tabs.sendMessage(tabId, { type: 'LINKSCOUT_SHOW_ERROR' })
      .catch(() => {}); // tab may have closed
  }
}

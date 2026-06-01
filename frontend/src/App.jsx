// App.jsx — the entire LinkScout frontend lives in this one file.
//
// React 101 for FastAPI developers:
//   - A "component" is a JavaScript function that returns HTML-like syntax (JSX).
//   - React automatically re-runs your component function whenever its state changes.
//   - That re-run updates what the user sees — no manual DOM manipulation, no
//     document.getElementById, no innerHTML. React handles all of that.
//   - Think of it like FastAPI's response model: you describe what the output
//     looks like for a given state, and the framework handles the rendering.

import { useState } from 'react'

// The backend URL. Vite's dev server runs on :5173, FastAPI on :8000.
// We call the FastAPI backend directly from the browser — the React app itself
// is just HTML/CSS/JS files served by Vite; it has no server-side logic.
const API_URL = 'http://localhost:8000/check'

// Verdict display metadata: the color and label for each of the five outcomes.
// These match the five string values that checker/core.py can return.
const VERDICT_META = {
  dangerous:   { color: '#f85149', label: 'DANGEROUS' },
  disputed:    { color: '#e3833c', label: 'DISPUTED' },
  suspicious:  { color: '#d29922', label: 'SUSPICIOUS' },
  likely_safe: { color: '#3fb950', label: 'LIKELY SAFE' },
  unknown:     { color: '#8b949e', label: 'UNKNOWN' },
}

// Quick sanity check run before we hit the network.
// The backend does thorough validation — this just saves a round-trip for
// obviously empty or malformed input.
function looksLikeUrl(input) {
  const s = input.trim()
  return s.length > 0 && (s.includes('.') || s.includes('://'))
}

// ─── App (root component) ────────────────────────────────────────────────────
//
// This is the component React mounts into <div id="root">.
// All state (the data that drives what the user sees) lives here and is passed
// down to child components as "props" — like keyword arguments to a function.
export default function App() {
  // useState(initialValue) returns [currentValue, setterFunction].
  // Calling the setter triggers a re-render with the new value.
  // Compare to Flutter's setState() — same idea, different syntax.
  const [url, setUrl]               = useState('')    // what's typed in the input
  const [loading, setLoading]       = useState(false) // true while the fetch is in-flight
  const [result, setResult]         = useState(null)  // the API response object, or null
  const [inputError, setInputError] = useState('')    // inline validation message
  const [networkError, setNetworkError] = useState('') // fetch / server-level errors

  async function handleCheck() {
    // Wipe the previous result and any error before running a new check.
    setResult(null)
    setNetworkError('')

    // Client-side validation — fail fast before touching the network.
    if (!url.trim()) {
      setInputError('Please enter a URL or domain.')
      return
    }
    if (!looksLikeUrl(url)) {
      setInputError("That doesn't look like a URL. Try https://example.com")
      return
    }
    setInputError('')

    setLoading(true)
    try {
      // fetch() is the browser's built-in HTTP client.
      // async/await is just syntactic sugar over Promises — same as Python's asyncio.
      const response = await fetch(API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url.trim() }),
      })

      // response.json() reads the response body and parses it as JSON.
      const data = await response.json()

      // The backend sets error: true with a message field when it rejects input
      // (e.g. a non-http scheme or a malformed domain). HTTP 422 also lands here
      // because fetch() doesn't throw on 4xx — it only throws on network failures.
      if (data.error) {
        setNetworkError(data.message || 'The backend rejected this input.')
      } else {
        setResult(data)
      }
    } catch (err) {
      // fetch() throws if the network call itself fails — server not running,
      // no internet connection, CORS blocked (before the response is received).
      setNetworkError(
        'Could not reach the LinkScout backend. Is it running on port 8000?'
      )
    } finally {
      // finally runs whether the try succeeded or threw — good place to clean up.
      setLoading(false)
    }
  }

  function handleReset() {
    setUrl('')
    setResult(null)
    setInputError('')
    setNetworkError('')
  }

  // Let the user submit with Enter, so they don't have to reach for the button.
  function handleKeyDown(e) {
    if (e.key === 'Enter') handleCheck()
  }

  // JSX looks like HTML but it's JavaScript. Two syntax differences matter here:
  //   className=  instead of  class=   (class is a reserved JS keyword)
  //   style={{}}  takes a JS object  (not a string like HTML's style="...")
  return (
    <div className="page">
      <header className="header">
        <h1 className="logo">LinkScout</h1>
        <p className="tagline">When in doubt, check it out.</p>
      </header>

      <main className="main">
        <div className="search-box">
          <input
            className={`url-input${inputError ? ' url-input--error' : ''}`}
            type="text"
            placeholder="https://example.com  or  example.com"
            value={url}
            // onChange fires on every keystroke. e.target.value is the current input text.
            onChange={e => setUrl(e.target.value)}
            onKeyDown={handleKeyDown}
            disabled={loading}
            aria-label="URL to check"
            autoFocus
          />
          <button
            className="check-btn"
            onClick={handleCheck}
            disabled={loading}
          >
            {/* Conditional rendering: show the spinner when loading, text otherwise */}
            {loading ? <Spinner /> : 'Check'}
          </button>
        </div>

        {/* Inline validation error — shown for empty or obviously malformed input */}
        {inputError && <p className="error-inline">{inputError}</p>}

        {/* Network / backend error — shown when fetch fails or backend returns error:true */}
        {networkError && (
          <div className="error-card">
            <span className="error-card__icon">⚠</span>
            <span className="error-card__text">{networkError}</span>
            <button className="error-card__retry" onClick={handleCheck}>
              Retry
            </button>
          </div>
        )}

        {/* Result — only rendered when result is not null (i.e. a successful check) */}
        {result && <ResultCard result={result} onReset={handleReset} />}
      </main>
    </div>
  )
}

// ─── Spinner ─────────────────────────────────────────────────────────────────
// A pure CSS spinning ring, no image or library needed.
// The spin animation is defined in App.css.
function Spinner() {
  return <span className="spinner" aria-label="Loading" />
}

// ─── ResultCard ──────────────────────────────────────────────────────────────
// Receives the full API response object and renders the verdict + breakdown.
//
// Props (the {result, onReset} in the function signature) are how React passes
// data from a parent component down to a child. Think of them as read-only
// arguments — the child reads them but never modifies them directly.
function ResultCard({ result, onReset }) {
  // Look up the display color and label for this verdict.
  // The ?? fallback handles any unexpected verdict string gracefully.
  const meta = VERDICT_META[result.verdict] ?? VERDICT_META.unknown

  return (
    // The result-card class has a CSS animation that fades it in when it first appears.
    <div className="result-card">
      {/* The verdict badge gets its color from a CSS custom property set inline.
          This pattern lets us drive the color from data without writing separate
          CSS rules for each verdict. */}
      <div
        className="verdict-badge"
        style={{ '--verdict-color': meta.color }}
      >
        {meta.label}
      </div>

      {/* Plain-English explanation generated by the backend */}
      <p className="explanation">{result.explanation}</p>

      {/* Two-column breakdown of what each source found */}
      <div className="sources">
        <VirusTotalBlock vt={result.sources.virustotal} />
        <URLhausBlock uh={result.sources.urlhaus} />
      </div>

      {/* Subtle metadata: which URL was checked, whether it was cached */}
      <div className="result-meta">
        <span className="result-meta__url" title={result.url}>
          {result.url}
        </span>
        <span className="result-meta__divider">·</span>
        {result.from_cache
          ? <span className="result-meta__cache">from cache</span>
          : <span className="result-meta__fresh">live result</span>
        }
      </div>

      <button className="reset-btn" onClick={onReset}>
        ← Check another URL
      </button>
    </div>
  )
}

// ─── VirusTotalBlock ──────────────────────────────────────────────────────────
// Renders the VirusTotal section of the source breakdown.
function VirusTotalBlock({ vt }) {
  const flagged = (vt.malicious || 0) + (vt.suspicious || 0)
  const hasData = vt.status === 'ok' && (vt.total_engines || 0) > 0

  return (
    <div className="source-block">
      <div className="source-block__header">
        <span className="source-block__name">VirusTotal</span>
        <span className={`source-block__verdict source-block__verdict--${vt.verdict}`}>
          {vt.verdict}
        </span>
      </div>
      <p className="source-block__detail">
        {hasData
          ? flagged > 0
            ? <><strong>{flagged}</strong> of {vt.total_engines} engines flagged</>
            : <>{vt.total_engines} engines — all clean</>
          : <span className="source-block__detail--muted">{vt.status}</span>
        }
      </p>
    </div>
  )
}

// ─── URLhausBlock ─────────────────────────────────────────────────────────────
// Renders the URLhaus section of the source breakdown.
function URLhausBlock({ uh }) {
  return (
    <div className="source-block">
      <div className="source-block__header">
        <span className="source-block__name">URLhaus</span>
        <span className={`source-block__verdict source-block__verdict--${uh.verdict}`}>
          {uh.verdict}
        </span>
      </div>
      <p className="source-block__detail">
        {uh.status !== 'ok'
          ? <span className="source-block__detail--muted">{uh.status}</span>
          : uh.found
          ? <>
              Found in feed
              {/* Optional chaining (?.) avoids a crash if threat_tags is missing */}
              {uh.threat_tags?.length > 0 && (
                <span className="tags">
                  {uh.threat_tags.map(tag => (
                    // key= is required when rendering a list — React uses it to
                    // track which items changed between renders.
                    <span key={tag} className="tag">{tag}</span>
                  ))}
                </span>
              )}
            </>
          : 'Not found in feed'
        }
      </p>
    </div>
  )
}

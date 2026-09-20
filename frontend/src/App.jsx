import { useState, useCallback, useRef, useEffect } from 'react'
import './App.css'

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:5000'
const POLL_INTERVAL_MS = 2000

const STEP_LABELS = {
  headers: 'Checking security headers…',
  ssl: 'Inspecting SSL/TLS certificate…',
  cms: 'Fingerprinting CMS and software…',
  scoring: 'Calculating score…',
}

async function api(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  const data = await res.json().catch(() => ({}))
  return { ok: res.ok, status: res.status, data }
}

function gradeTier(grade) {
  if (grade.startsWith('A')) return 'high'
  if (grade.startsWith('B') || grade.startsWith('C')) return 'mid'
  return 'low'
}

const TIER_COLOR = { high: 'var(--pass)', mid: 'var(--warn)', low: 'var(--fail)' }

/* ---------- gauge ---------- */

function ScoreGauge({ score, grade }) {
  // semicircle gauge, 0-100 mapped to a 180-degree arc
  const radius = 70
  const circumference = Math.PI * radius
  const filled = (score / 100) * circumference
  const tierColor = { high: 'var(--pass)', mid: 'var(--warn)', low: 'var(--fail)' }[gradeTier(grade)]

  return (
    <svg className="gauge" viewBox="0 0 170 100" aria-hidden="true">
      <path
        d="M 15 90 A 70 70 0 0 1 155 90"
        fill="none"
        stroke="var(--paper)"
        strokeWidth="14"
        strokeLinecap="round"
      />
      <path
        d="M 15 90 A 70 70 0 0 1 155 90"
        fill="none"
        stroke={tierColor}
        strokeWidth="14"
        strokeLinecap="round"
        strokeDasharray={`${filled} ${circumference}`}
        className="gauge-fill"
      />
      <text x="85" y="78" textAnchor="middle" className="gauge-score">{score}</text>
    </svg>
  )
}

function GradeBadge({ grade }) {
  return (
    <div className="grade-badge" data-tier={gradeTier(grade)}>
      {grade}
    </div>
  )
}

function CheckList({ title, items, kind }) {
  if (!items || items.length === 0) return null
  return (
    <div className={`check-list check-list--${kind}`}>
      <h3>{title}</h3>
      <ul>
        {items.map((item, i) => (
          <li key={i}>
            <span className="check-name">
              {item.check}
              {item.value ? <span className="check-value"> — {item.value}</span> : null}
            </span>
            {item.how_to_fix && <p className="check-fix">{item.how_to_fix}</p>}
          </li>
        ))}
      </ul>
    </div>
  )
}

function ScoreBreakdown({ breakdown, maxBreakdown }) {
  const rows = [
    { key: 'headers', label: 'Headers' },
    { key: 'ssl', label: 'SSL/TLS' },
    { key: 'cms', label: 'CMS' },
  ]
  return (
    <div className="breakdown">
      {rows.map(({ key, label }) => {
        const earned = breakdown[key]
        const max = maxBreakdown[key]
        const pct = max ? Math.round((earned / max) * 100) : 0
        return (
          <div className="breakdown-row" key={key}>
            <span className="breakdown-label">{label}</span>
            <div className="breakdown-bar">
              <div className="breakdown-bar-fill" style={{ width: `${pct}%` }} />
            </div>
            <span className="breakdown-score">
              {earned}/{max}
            </span>
          </div>
        )
      })}
    </div>
  )
}

function ReportView({ report, url, pdfUrl, onSaveToHistory, saveState, isLoggedIn }) {
  return (
    <div className="report">
      <div className="report-header">
        <ScoreGauge score={report.score} grade={report.grade} />
        <div className="report-header-text">
          <div className="report-url">{url}</div>
          <div className="report-score">
            {report.score}
            <span className="report-score-max">/100</span>
          </div>
        </div>
        <GradeBadge grade={report.grade} />
      </div>

      <ScoreBreakdown breakdown={report.breakdown} maxBreakdown={report.max_breakdown} />

      <div className="report-actions">
        <a className="btn-secondary" href={pdfUrl} target="_blank" rel="noreferrer">
          Download PDF
        </a>
        {isLoggedIn && onSaveToHistory && (
          <button className="btn-secondary" onClick={onSaveToHistory} disabled={saveState === 'saving' || saveState === 'saved'}>
            {saveState === 'saved' ? 'Saved to history ✓' : saveState === 'saving' ? 'Saving…' : 'Save to history'}
          </button>
        )}
      </div>

      <CheckList title="Passed checks" items={report.passed_checks} kind="passed" />
      <CheckList title="Needs attention" items={report.failed_checks} kind="failed" />
    </div>
  )
}

/* ---------- auth ---------- */

function AuthBar({ user, onLoggedIn, onLoggedOut, view, setView }) {
  const [mode, setMode] = useState('login') // login | register
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  const submit = async (e) => {
    e.preventDefault()
    setError(null)
    setBusy(true)
    const path = mode === 'login' ? '/api/auth/login' : '/api/auth/register'
    const { ok, data } = await api(path, { method: 'POST', body: JSON.stringify({ username, password }) })
    setBusy(false)
    if (!ok) {
      setError(data.error || 'Something went wrong.')
      return
    }
    setUsername('')
    setPassword('')
    onLoggedIn(data.username)
  }

  const logout = async () => {
    await api('/api/auth/logout', { method: 'POST' })
    onLoggedOut()
  }

  if (user) {
    return (
      <div className="auth-bar">
        <span className="auth-user">Signed in as <strong>{user}</strong></span>
        <nav className="auth-nav">
          <button className={`link-btn ${view === 'scan' ? 'active' : ''}`} onClick={() => setView('scan')}>Scan</button>
          <button className={`link-btn ${view === 'history' ? 'active' : ''}`} onClick={() => setView('history')}>History</button>
          <button className="link-btn" onClick={logout}>Log out</button>
        </nav>
      </div>
    )
  }

  return (
    <div className="auth-bar">
      <form className="auth-form" onSubmit={submit}>
        <input
          type="text"
          placeholder="username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          disabled={busy}
          required
        />
        <input
          type="password"
          placeholder="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          disabled={busy}
          required
        />
        <button type="submit" disabled={busy}>{mode === 'login' ? 'Log in' : 'Register'}</button>
        <button
          type="button"
          className="link-btn"
          onClick={() => { setMode(mode === 'login' ? 'register' : 'login'); setError(null) }}
        >
          {mode === 'login' ? 'Need an account?' : 'Have an account?'}
        </button>
      </form>
      {error && <span className="auth-error">{error}</span>}
    </div>
  )
}

/* ---------- score trend ---------- */

function ScoreTrend({ entries }) {
  // The chart plots oldest to newest, so sort by scan date.
  const counts = {}
  entries.forEach((e) => { counts[e.url] = (counts[e.url] || 0) + 1 })
  const sites = Object.keys(counts)
  // Default to the site scanned most often (ties go to the most recent one).
  const defaultSite = sites.reduce((best, s) => (counts[s] > counts[best] ? s : best), sites[0])
  const [picked, setPicked] = useState(null)
  const site = sites.includes(picked) ? picked : defaultSite

  const points = entries
    .filter((e) => e.url === site)
    .sort((a, b) => new Date(a.scanned_at) - new Date(b.scanned_at))
  const n = points.length

  const W = 600
  const H = 220
  const pad = { top: 24, right: 20, bottom: 30, left: 38 }
  const innerW = W - pad.left - pad.right
  const innerH = H - pad.top - pad.bottom
  const x = (i) => (n === 1 ? pad.left + innerW / 2 : pad.left + (i * innerW) / (n - 1))
  const y = (score) => pad.top + innerH * (1 - score / 100)
  const formatDay = (iso) => new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })

  const first = points[0].score
  const last = points[n - 1].score
  const change = last - first

  let summary
  if (n < 2) summary = 'Save at least two scans of this site to see how its score changes.'
  else if (change > 0) summary = `Score rose from ${first} to ${last} (up ${change} points) over ${n} scans.`
  else if (change < 0) summary = `Score fell from ${first} to ${last} (down ${-change} points) over ${n} scans.`
  else summary = `Score held at ${last} over ${n} scans.`

  return (
    <section className="trend">
      <div className="trend-head">
        <h3>Score over time</h3>
        {sites.length > 1 ? (
          <select
            className="trend-select"
            value={site}
            onChange={(e) => setPicked(e.target.value)}
            aria-label="Site to chart"
          >
            {sites.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        ) : (
          <span className="trend-site mono-cell">{site}</span>
        )}
      </div>

      <p className="trend-summary">{summary}</p>

      {n >= 2 && (
        <svg className="trend-chart" viewBox={`0 0 ${W} ${H}`} role="img" aria-label={summary}>
          {[0, 25, 50, 75, 100].map((tick) => (
            <g key={tick}>
              <line x1={pad.left} x2={W - pad.right} y1={y(tick)} y2={y(tick)} className="trend-grid" />
              <text x={pad.left - 8} y={y(tick) + 4} textAnchor="end" className="trend-tick">{tick}</text>
            </g>
          ))}

          <polyline
            className="trend-line"
            fill="none"
            points={points.map((p, i) => `${x(i)},${y(p.score)}`).join(' ')}
          />

          {points.map((p, i) => (
            <circle
              key={p.id}
              className="trend-point"
              cx={x(i)}
              cy={y(p.score)}
              r={i === n - 1 ? 6 : 4}
              fill={TIER_COLOR[gradeTier(p.grade)]}
            >
              <title>{`${formatDay(p.scanned_at)}: ${p.score}/100 (${p.grade})`}</title>
            </circle>
          ))}

          <text x={x(n - 1)} y={y(last) - 12} textAnchor="middle" className="trend-last">{last}</text>
          <text x={pad.left} y={H - 8} textAnchor="start" className="trend-tick">{formatDay(points[0].scanned_at)}</text>
          <text x={W - pad.right} y={H - 8} textAnchor="end" className="trend-tick">{formatDay(points[n - 1].scanned_at)}</text>
        </svg>
      )}
    </section>
  )
}

/* ---------- history ---------- */

function HistoryView({ onSelect }) {
  const [entries, setEntries] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    api('/api/history').then(({ ok, data }) => {
      if (!ok) { setError(data.error || 'Could not load history.'); return }
      setEntries(data.history)
    })
  }, [])

  if (error) return <div className="error-box">{error}</div>
  if (!entries) return <p className="muted">Loading history…</p>
  if (entries.length === 0) return <p className="muted">No scans saved yet. Run a scan and save it to see it here.</p>

  return (
    <>
      <ScoreTrend entries={entries} />
      <table className="history-table">
        <thead>
          <tr><th>Site</th><th>Score</th><th>Grade</th><th>Scanned</th><th></th></tr>
        </thead>
        <tbody>
          {entries.map((entry) => (
            <tr key={entry.id}>
              <td className="mono-cell">{entry.url}</td>
              <td>{entry.score}/100</td>
              <td>
                <span className="grade-chip" data-tier={gradeTier(entry.grade)}>{entry.grade}</span>
              </td>
              <td className="muted">{new Date(entry.scanned_at).toLocaleDateString()}</td>
              <td><button className="link-btn" onClick={() => onSelect(entry.id)}>View</button></td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  )
}

/* ---------- main app ---------- */

export default function App() {
  const [url, setUrl] = useState('')
  // idle | queued | progress | success | error
  const [status, setStatus] = useState('idle')
  const [step, setStep] = useState(null)
  const [error, setError] = useState(null)
  const [result, setResult] = useState(null)
  const [scanId, setScanId] = useState(null)
  const [saveState, setSaveState] = useState('idle') // idle | saving | saved

  const [user, setUser] = useState(null)
  const [view, setView] = useState('scan') // scan | history
  const [historyDetail, setHistoryDetail] = useState(null)

  const activeScanRef = useRef(0)

  useEffect(() => {
    api('/api/auth/me').then(({ data }) => {
      if (data.logged_in) setUser(data.username)
    })
  }, [])

  useEffect(() => () => {
    activeScanRef.current += 1
  }, [])

  const pollStatus = useCallback((id, scanGeneration) => {
    const poll = async () => {
      if (activeScanRef.current !== scanGeneration) return

      try {
        const { data } = await api(`/api/scan/${id}/status`)
        if (activeScanRef.current !== scanGeneration) return

        if (data.state === 'PROGRESS') {
          setStep(data.step)
          setTimeout(poll, POLL_INTERVAL_MS)
        } else if (data.state === 'SUCCESS') {
          setStatus('success')
          setResult(data.result)
        } else if (data.state === 'FAILURE') {
          setStatus('error')
          setError(data.error || 'The scan failed. Try again.')
        } else {
          setTimeout(poll, POLL_INTERVAL_MS)
        }
      } catch {
        if (activeScanRef.current !== scanGeneration) return
        setStatus('error')
        setError('Lost connection to the scan server.')
      }
    }
    poll()
  }, [])

  const handleSubmit = async (e) => {
    e.preventDefault()
    activeScanRef.current += 1
    const scanGeneration = activeScanRef.current

    setError(null)
    setResult(null)
    setStep(null)
    setScanId(null)
    setSaveState('idle')
    setStatus('queued')

    const { ok, data } = await api('/api/scan', { method: 'POST', body: JSON.stringify({ url }) })
    if (activeScanRef.current !== scanGeneration) return

    if (!ok) {
      setStatus('error')
      setError(data.error || 'Could not start the scan.')
      return
    }

    setScanId(data.scan_id)
    setStatus('progress')
    pollStatus(data.scan_id, scanGeneration)
  }

  const saveToHistory = async () => {
    if (!scanId) return
    setSaveState('saving')
    const { ok } = await api('/api/history', { method: 'POST', body: JSON.stringify({ scan_id: scanId }) })
    setSaveState(ok ? 'saved' : 'idle')
  }

  const openHistoryEntry = async (id) => {
    const { ok, data } = await api(`/api/history/${id}`)
    if (ok) setHistoryDetail(data)
  }

  const isScanning = status === 'queued' || status === 'progress'

  return (
    <div className="app">
      <header className="app-header">
        <h1>VulnScan Lite</h1>
        <p className="tagline">A passive security health check for any website.</p>
        <p className="disclaimer">Only scan websites you own. This tool performs passive analysis only.</p>
      </header>

      <AuthBar
        user={user}
        onLoggedIn={(name) => { setUser(name); setView('scan') }}
        onLoggedOut={() => { setUser(null); setView('scan'); setHistoryDetail(null) }}
        view={view}
        setView={setView}
      />

      {view === 'scan' && (
        <>
          <form className="scan-form" onSubmit={handleSubmit}>
            <input
              type="url"
              required
              placeholder="https://example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              disabled={isScanning}
              aria-label="Website URL to scan"
            />
            <button type="submit" disabled={isScanning}>
              {isScanning ? 'Scanning…' : 'Scan'}
            </button>
          </form>

          {isScanning && (
            <div className="scanning-indicator" role="status" aria-live="polite">
              <div className="spinner" />
              <p key={step || 'queued'}>{step ? STEP_LABELS[step] || 'Scanning…' : 'Queuing scan…'}</p>
            </div>
          )}

          {status === 'error' && (
            <div className="error-box" role="alert">{error}</div>
          )}

          {status === 'success' && result && (
            <ReportView
              report={result.report}
              url={result.url}
              pdfUrl={`${API_BASE}/api/scan/${scanId}/pdf`}
              onSaveToHistory={saveToHistory}
              saveState={saveState}
              isLoggedIn={!!user}
            />
          )}
        </>
      )}

      {view === 'history' && !historyDetail && (
        <HistoryView onSelect={openHistoryEntry} />
      )}

      {view === 'history' && historyDetail && (
        <>
          <button className="link-btn" onClick={() => setHistoryDetail(null)}>&larr; Back to history</button>
          <ReportView
            report={historyDetail.result.report}
            url={historyDetail.result.url}
            pdfUrl={`${API_BASE}/api/history/${historyDetail.id}/pdf`}
            isLoggedIn={false}
          />
        </>
      )}
    </div>
  )
}

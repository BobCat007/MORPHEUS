import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Activity, AlertTriangle, ArrowUpRight,
  Bell, CheckCircle2, Clock3, Crosshair,
  ExternalLink, FileSearch, Filter, LayoutDashboard, LoaderCircle,
  Menu, Radio, RefreshCw, Search, Shield, ShieldAlert,
  ShieldCheck, Siren, Target, X, Terminal, Eye, UserRound
} from 'lucide-react'
import './App.css'

const API = '/api/v1'
const STATUSES = ['open', 'acknowledged', 'investigating', 'resolved']
const SEVERITIES = ['critical', 'high', 'medium', 'low']

const severityStyle = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
}

const statusStyle = {
  open: 'status-open',
  acknowledged: 'status-acknowledged',
  investigating: 'status-investigating',
  resolved: 'status-resolved',
}

function getAlertData(alert) {
  return alert?.data && typeof alert.data === 'object' ? alert.data : alert || {}
}

function getAlertId(alert) {
  const data = getAlertData(alert)
  return data.alert_id || data.id || alert?.event_id || 'Unknown'
}

function getIncidentId(incident) {
  return incident?.incident_id || incident?.id || incident?.incidentId || 'Unknown'
}

function getSessionData(event) {
  return event?.data && typeof event.data === 'object' ? event.data : event || {}
}

function getSessionInfo(event) {
  const data = getSessionData(event)
  return data.session || data
}

function getRisk(event) {
  const data = getSessionData(event)
  return data.risk_assessment || {}
}

function getSessionId(event) {
  return getSessionInfo(event).session_id || getRisk(event).session_id || event?.event_id || 'Unknown'
}

function formatDate(value) {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return String(value)
  return date.toLocaleString([], {
    month: 'short',
    day: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

function shortId(value) {
  const text = String(value || 'Unknown')
  return text.length > 18 ? `${text.slice(0, 18)}…` : text
}

function SeverityBadge({ severity }) {
  const value = String(severity || 'unknown').toLowerCase()
  return (
    <span className={`badge severity-${severityStyle[value] || 'unknown'}`}>
      <span className="badge-dot" />
      {value}
    </span>
  )
}

function StatusBadge({ status }) {
  const value = String(status || 'open').toLowerCase()
  return (
    <span className={`badge ${statusStyle[value] || 'status-open'}`}>
      {value}
    </span>
  )
}

function MetricCard({ title, value, subtitle, icon: Icon, tone, trend }) {
  return (
    <article className="metric-card">
      <div className="metric-top">
        <span className="metric-label">{title}</span>
        <span className={`metric-icon ${tone}`}><Icon size={19} /></span>
      </div>
      <div className="metric-value">{value ?? '—'}</div>
      <div className="metric-footer">
        <span>{subtitle}</span>
        {trend && <span className="metric-trend"><ArrowUpRight size={14} /> Live</span>}
      </div>
    </article>
  )
}

function SectionTitle({ eyebrow, title, description, action }) {
  return (
    <div className="section-title">
      <div>
        <div className="eyebrow">{eyebrow}</div>
        <h2>{title}</h2>
        {description && <p>{description}</p>}
      </div>
      {action}
    </div>
  )
}

function EmptyState({ icon: Icon = FileSearch, title, message }) {
  return (
    <div className="empty-state">
      <span className="empty-icon"><Icon size={25} /></span>
      <strong>{title}</strong>
      <p>{message}</p>
    </div>
  )
}

function SessionTable({ sessions, loading, onSelect, compact = false }) {
  if (loading) {
    return <div className="loading-state"><LoaderCircle className="spin" size={22} /> Loading analyzed sessions…</div>
  }

  if (!sessions.length) {
    return (
      <EmptyState
        icon={Eye}
        title="No analyzed sessions found"
        message="Sessions appear here after the MORPHEUS intelligence pipeline analyzes a honeypot session. Try changing your filters or refreshing the data."
      />
    )
  }

  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>SESSION</th>
            <th>SOURCE IP</th>
            <th>USERNAME</th>
            <th>RISK</th>
            <th>INTENT</th>
            {!compact && <th>TIME</th>}
            <th />
          </tr>
        </thead>
        <tbody>
          {sessions.map((event, index) => {
            const session = getSessionInfo(event)
            const risk = getRisk(event)
            const data = getSessionData(event)
            const intents = Array.isArray(data.intents) ? data.intents : []
            const intentLabel = intents.map((item) => item.intent).filter(Boolean).join(', ') || 'Unclassified'

            return (
              <tr key={`${getSessionId(event)}-${index}`}>
                <td>
                  <div className="table-primary">{shortId(getSessionId(event))}</div>
                  <div className="table-secondary">{String(session.protocol || 'unknown').toUpperCase()} session</div>
                </td>
                <td><span className="mono">{session.source_ip || risk.source_ip || '—'}</span></td>
                <td>{session.username || '—'}</td>
                <td>
                  <div style={{ display: 'grid', gap: 5, minWidth: 72 }}>
                    <SeverityBadge severity={risk.severity} />
                    <span className="mono">{risk.score ?? '—'}/100</span>
                  </div>
                </td>
                <td>{intentLabel}</td>
                {!compact && <td>{formatDate(event.timestamp || session.end_time)}</td>}
                <td><button className="row-action" onClick={() => onSelect(event)}>Inspect <ArrowUpRight size={14} /></button></td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function SessionDetails({ event, onClose }) {
  const data = getSessionData(event)
  const session = getSessionInfo(event)
  const risk = getRisk(event)
  const fingerprint = data.fingerprint || {}
  const intents = Array.isArray(data.intents) ? data.intents : []
  const techniques = Array.isArray(data.mitre_techniques) ? data.mitre_techniques : []
  const factors = Array.isArray(risk.factors) ? risk.factors : []
  const actions = Array.isArray(data.recommended_actions) ? data.recommended_actions : []
  const commands = Array.isArray(session.commands) ? session.commands : []
  const duration = session.duration_ms == null
    ? '—'
    : `${(session.duration_ms / 1000).toFixed(1)} sec`

  return (
    <div className="modal-scrim" onMouseDown={(event) => {
      if (event.target === event.currentTarget) onClose()
    }}>
      <section
        className="incident-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="session-modal-title"
        style={{ width: 'min(100%, 780px)', maxHeight: '90vh', overflowY: 'auto' }}
      >
        <div className="modal-header">
          <div>
            <div className="eyebrow">SESSION INTELLIGENCE</div>
            <h2 id="session-modal-title">Analyzed session</h2>
          </div>
          <button className="icon-button" onClick={onClose} aria-label="Close session details"><X size={19} /></button>
        </div>

        <div className="modal-incident-id">{getSessionId(event)}</div>

        <div className="metrics-grid" style={{ gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', marginTop: 16 }}>
          <div className="metric-card">
            <div className="metric-label">Risk score</div>
            <div className="metric-value">{risk.score ?? '—'}<span style={{ fontSize: 12, color: '#7e8fa6' }}>/100</span></div>
            <SeverityBadge severity={risk.severity} />
          </div>
          <div className="metric-card">
            <div className="metric-label">Source IP</div>
            <div className="metric-value" style={{ fontSize: 17, overflowWrap: 'anywhere' }}>{session.source_ip || risk.source_ip || '—'}</div>
            <div className="metric-footer">{String(session.protocol || 'unknown').toUpperCase()} protocol</div>
          </div>
          <div className="metric-card">
            <div className="metric-label">Session duration</div>
            <div className="metric-value" style={{ fontSize: 20 }}>{duration}</div>
            <div className="metric-footer">{session.authentication_success ? 'Authentication succeeded' : 'Authentication status unknown'}</div>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 14, marginTop: 18 }}>
          <section className="panel" style={{ padding: 16 }}>
            <SectionTitle eyebrow="SESSION PROFILE" title="Connection details" />
            <div style={{ display: 'grid', gap: 12, fontSize: 11 }}>
              <div><div className="table-secondary">Username</div><strong>{session.username || '—'}</strong></div>
              <div><div className="table-secondary">Client version</div><span className="mono" style={{ overflowWrap: 'anywhere' }}>{session.client_version || '—'}</span></div>
              <div><div className="table-secondary">Started</div>{formatDate(session.start_time)}</div>
              <div><div className="table-secondary">Ended</div>{formatDate(session.end_time || event.timestamp)}</div>
              <div><div className="table-secondary">Fingerprint ID</div><span className="mono">{fingerprint.fingerprint_id || risk.fingerprint_id || '—'}</span></div>
              <div><div className="table-secondary">HASSH</div><span className="mono" style={{ overflowWrap: 'anywhere' }}>{session.hassh || fingerprint.hassh || '—'}</span></div>
            </div>
          </section>

          <section className="panel" style={{ padding: 16 }}>
            <SectionTitle eyebrow="BEHAVIOR" title="Observed commands" />
            {commands.length ? (
              <div style={{ display: 'grid', gap: 7 }}>
                {commands.map((command, index) => (
                  <div key={`${command}-${index}`} style={{ display: 'flex', alignItems: 'center', gap: 9, padding: '9px 10px', border: '1px solid #233348', borderRadius: 6, background: '#101b29' }}>
                    <Terminal size={14} color="#79b9fa" />
                    <code style={{ color: '#d3e0f0', fontSize: 11, overflowWrap: 'anywhere' }}>{command}</code>
                  </div>
                ))}
              </div>
            ) : <p className="welcome-description">No commands recorded.</p>}
          </section>
        </div>

        <section className="panel" style={{ padding: 16, marginTop: 14 }}>
          <SectionTitle eyebrow="DETECTED BEHAVIOR" title="Intent classification" />
          {intents.length ? (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
              {intents.map((item, index) => (
                <div key={`${item.intent}-${index}`} style={{ border: '1px solid #294765', borderRadius: 7, padding: '10px 12px', background: '#14263a', minWidth: 130 }}>
                  <div style={{ color: '#a9d2ff', fontSize: 11, fontWeight: 600 }}>{item.intent || 'Unknown intent'}</div>
                  <div className="table-secondary">Phase: {item.phase || '—'}</div>
                  <div className="table-secondary">Confidence: {Math.round((item.confidence ?? 0) * 100)}%</div>
                  {item.evidence?.length > 0 && <div className="table-secondary">Evidence: {item.evidence.join(', ')}</div>}
                </div>
              ))}
            </div>
          ) : <p className="welcome-description">No intent classifications recorded.</p>}
        </section>

        <section className="panel" style={{ padding: 16, marginTop: 14 }}>
          <SectionTitle eyebrow="MITRE ATT&CK" title="Mapped techniques" />
          {techniques.length ? (
            <div style={{ display: 'grid', gap: 9 }}>
              {techniques.map((item, index) => (
                <div key={`${item.technique_id}-${index}`} style={{ padding: 11, border: '1px solid #29394b', borderRadius: 7, background: '#101925' }}>
                  <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 8 }}>
                    <span className="mono">{item.technique_id || '—'}</span>
                    <strong style={{ fontSize: 11, color: '#dbe6f5' }}>{item.technique_name || 'Unnamed technique'}</strong>
                  </div>
                  <div className="table-secondary">Tactic: {item.tactic || '—'}</div>
                  {item.evidence?.length > 0 && <div className="table-secondary">Evidence: {item.evidence.join(', ')}</div>}
                </div>
              ))}
            </div>
          ) : <p className="welcome-description">No MITRE ATT&CK techniques mapped.</p>}
        </section>

        <section className="panel" style={{ padding: 16, marginTop: 14 }}>
          <SectionTitle eyebrow="RISK EXPLANATION" title="Assessment factors" />
          {factors.length ? (
            <div style={{ display: 'grid', gap: 8 }}>
              {factors.map((factor, index) => (
                <div key={`${factor.name}-${index}`} className="status-summary-row">
                  <span className="status-icon status-investigating"><AlertTriangle size={15} /></span>
                  <span className="status-summary-label">
                    <strong style={{ display: 'block', color: '#dce6f4', marginBottom: 4 }}>{factor.name || factor.category || 'Risk factor'}</strong>
                    <span className="table-secondary">{factor.evidence?.join(', ') || factor.category || 'Assessment factor'}</span>
                  </span>
                  <strong>+{factor.score ?? 0}</strong>
                </div>
              ))}
            </div>
          ) : <p className="welcome-description">No risk factors provided.</p>}
        </section>

        <section className="panel" style={{ padding: 16, marginTop: 14 }}>
          <SectionTitle eyebrow="RECOMMENDED RESPONSE" title="Suggested actions" />
          {actions.length ? (
            <div style={{ display: 'grid', gap: 8 }}>
              {actions.map((action, index) => (
                <div key={`${action.name}-${index}`} className="status-summary-row">
                  <span className="status-icon status-acknowledged"><ShieldCheck size={15} /></span>
                  <span className="status-summary-label">
                    <strong style={{ display: 'block', color: '#dce6f4', marginBottom: 4 }}>{action.name || 'Recommended action'}</strong>
                    <span className="table-secondary">{action.description || action.category || 'No description available.'}</span>
                  </span>
                  <span className="mono">P{action.priority ?? '—'}</span>
                </div>
              ))}
            </div>
          ) : <p className="welcome-description">No recommended actions recorded.</p>}
          <p className="modal-help">These are recorded recommendations. This dashboard does not automatically execute them.</p>
        </section>

        <div className="modal-actions">
          <button className="button-secondary" onClick={onClose}>Close details</button>
        </div>
      </section>
    </div>
  )
}

export default function App() {
  const [page, setPage] = useState('overview')
  const [dashboard, setDashboard] = useState(null)
  const [alerts, setAlerts] = useState([])
  const [incidents, setIncidents] = useState([])
  const [sessions, setSessions] = useState([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('all')
  const [selectedIncident, setSelectedIncident] = useState(null)
  const [selectedSession, setSelectedSession] = useState(null)
  const [updatingIncident, setUpdatingIncident] = useState(false)
  const [mobileNavOpen, setMobileNavOpen] = useState(false)
  const [notice, setNotice] = useState('')

  const loadData = useCallback(async (quiet = false) => {
    if (quiet) setRefreshing(true)
    else setLoading(true)
    setError('')

    try {
      const endpoints = [
        `${API}/dashboard`,
        `${API}/alerts?limit=100`,
        `${API}/incidents?limit=100`,
        `${API}/sessions?limit=100`,
      ]
      const responses = await Promise.all(endpoints.map((url) => fetch(url)))
      const failed = responses.find((response) => !response.ok)

      if (failed) {
        throw new Error(`API returned HTTP ${failed.status}. Is the MORPHEUS API running?`)
      }

      const [dashboardData, alertsData, incidentsData, sessionsData] = await Promise.all(
        responses.map((response) => response.json())
      )

      setDashboard(dashboardData)
      setAlerts(Array.isArray(alertsData.items) ? alertsData.items : [])
      setIncidents(Array.isArray(incidentsData.items) ? incidentsData.items : [])
      setSessions(Array.isArray(sessionsData.items) ? sessionsData.items : [])
    } catch (err) {
      setError(err.message || 'Unable to connect to the MORPHEUS API.')
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [])

  useEffect(() => {
    loadData()
  }, [loadData])

  useEffect(() => {
    let socket
    let reconnectTimer
    let refreshTimer
    let disposed = false
    let retryDelay = 1000

    const connect = () => {
      if (disposed) return

      const scheme = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      socket = new WebSocket(`${scheme}//${window.location.host}${API}/stream`)

      socket.onopen = () => {
        retryDelay = 1000
      }

      socket.onmessage = (message) => {
        let event
        try {
          event = JSON.parse(message.data)
        } catch {
          return
        }

        if (event?.type === 'stream.connected') return

        // Batch bursts of events into one REST refresh.
        if (refreshTimer) return
        refreshTimer = window.setTimeout(() => {
          refreshTimer = null
          if (!disposed) loadData(true)
        }, 300)
      }

      socket.onclose = () => {
        if (disposed) return
        reconnectTimer = window.setTimeout(connect, retryDelay)
        retryDelay = Math.min(retryDelay * 2, 30000)
      }

      socket.onerror = () => {
        socket?.close()
      }
    }

    connect()

    return () => {
      disposed = true
      socket?.close()
      window.clearTimeout(reconnectTimer)
      window.clearTimeout(refreshTimer)
    }
  }, [loadData])

  const visibleAlerts = useMemo(() => {
    const query = search.trim().toLowerCase()
    return alerts.filter((alert) => {
      const data = getAlertData(alert)
      const severity = String(data.severity || 'unknown').toLowerCase()
      const searchable = [
        getAlertId(alert), data.source_ip, data.session_id,
        data.summary, data.reason, data.message,
      ].filter(Boolean).join(' ').toLowerCase()

      return (severityFilter === 'all' || severity === severityFilter)
        && (!query || searchable.includes(query))
    })
  }, [alerts, search, severityFilter])

  const visibleIncidents = useMemo(() => {
    const query = search.trim().toLowerCase()
    return incidents.filter((incident) => {
      const searchable = [
        getIncidentId(incident), incident.alert_id, incident.status,
        incident.source_ip, incident.title,
      ].filter(Boolean).join(' ').toLowerCase()

      return (statusFilter === 'all' || incident.status === statusFilter)
        && (!query || searchable.includes(query))
    })
  }, [incidents, search, statusFilter])

  const visibleSessions = useMemo(() => {
    const query = search.trim().toLowerCase()
    return sessions.filter((event) => {
      const session = getSessionInfo(event)
      const risk = getRisk(event)
      const data = getSessionData(event)
      const severity = String(risk.severity || 'unknown').toLowerCase()
      const intents = Array.isArray(data.intents) ? data.intents : []
      const techniques = Array.isArray(data.mitre_techniques) ? data.mitre_techniques : []
      const searchable = [
        getSessionId(event),
        session.source_ip,
        session.username,
        session.protocol,
        session.client_version,
        risk.fingerprint_id,
        ...intents.map((item) => item.intent),
        ...techniques.map((item) => `${item.technique_id} ${item.technique_name}`),
        ...(Array.isArray(session.commands) ? session.commands : []),
      ].filter(Boolean).join(' ').toLowerCase()

      return (severityFilter === 'all' || severity === severityFilter)
        && (!query || searchable.includes(query))
    })
  }, [sessions, search, severityFilter])

  const severityCounts = dashboard?.alerts_by_severity || {}
  const sessionSeverityCounts = dashboard?.sessions_by_severity || {}
  const totalAlerts = dashboard?.total_alerts ?? alerts.length
  const totalIncidents = dashboard?.total_incidents ?? incidents.length
  const totalSessions = dashboard?.total_analyzed_sessions ?? sessions.length
  const activeIncidents = incidents.filter((item) => item.status !== 'resolved').length
  const criticalCount = (severityCounts.critical ?? 0) + (severityCounts.high ?? 0)
  const severityTotal = SEVERITIES.reduce((sum, key) => sum + (severityCounts[key] || 0), 0)

  async function openSession(event) {
    setSelectedSession(event)
    const sessionId = getSessionId(event)

    try {
      const response = await fetch(`${API}/sessions/${encodeURIComponent(sessionId)}`)
      if (!response.ok) return
      const detail = await response.json()
      setSelectedSession(detail.item || detail.session || detail)
    } catch {
      // The list entry still contains enough information to inspect the session.
    }
  }

  async function changeIncidentStatus(incident, status) {
    setUpdatingIncident(true)
    setNotice('')

    try {
      const response = await fetch(
        `${API}/incidents/${encodeURIComponent(getIncidentId(incident))}/status`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            status,
            actor: 'dashboard-analyst',
            note: 'Updated from the MORPHEUS dashboard',
          }),
        }
      )

      const result = await response.json()
      if (!response.ok) {
        throw new Error(result.detail || `Update failed with HTTP ${response.status}`)
      }

      setNotice(`Incident status updated to ${status}.`)
      setSelectedIncident(null)
      await loadData(true)
    } catch (err) {
      setError(err.message || 'Could not update incident status.')
    } finally {
      setUpdatingIncident(false)
    }
  }

  function navigate(nextPage) {
    setPage(nextPage)
    setSearch('')
    setMobileNavOpen(false)
    setNotice('')
  }

  const navItems = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'sessions', label: 'Analyzed sessions', icon: Eye, count: totalSessions },
    { id: 'alerts', label: 'Security alerts', icon: Siren, count: totalAlerts },
    { id: 'incidents', label: 'Incidents', icon: ShieldAlert, count: activeIncidents },
  ]

  const comingSoon = {
    intel: {
      icon: Crosshair,
      title: 'Threat intelligence',
      description: 'A unified view for attacker fingerprints, campaign correlations, and MITRE ATT&CK mappings.',
      tag: 'NEXT MODULE',
    },
    activity: {
      icon: Activity,
      title: 'System activity',
      description: 'A timeline for incoming honeypot events, session reconstruction, and detection activity.',
      tag: 'NEXT MODULE',
    },
  }

  const currentPageTitle = navItems.find((item) => item.id === page)?.label
    || comingSoon[page]?.title
    || 'MORPHEUS'

  return (
    <div className="app-shell">
      {mobileNavOpen && <button className="mobile-scrim" aria-label="Close navigation" onClick={() => setMobileNavOpen(false)} />}

      <aside className={`sidebar ${mobileNavOpen ? 'sidebar-open' : ''}`}>
        <div className="brand">
          <div className="brand-mark"><Shield size={23} strokeWidth={2.1} /></div>
          <div className="brand-copy">
            <span className="brand-name">MORPHEUS</span>
            <span className="brand-subtitle">THREAT DEFENSE PLATFORM</span>
          </div>
          <button className="icon-button sidebar-close" onClick={() => setMobileNavOpen(false)} aria-label="Close menu"><X size={18} /></button>
        </div>

        <div className="workspace-label">WORKSPACE</div>
        <nav className="primary-nav" aria-label="Main navigation">
          {navItems.map(({ id, label, icon: Icon, count }) => (
            <button key={id} className={`nav-item ${page === id ? 'active' : ''}`} onClick={() => navigate(id)}>
              <Icon size={18} />
              <span>{label}</span>
              {count !== undefined && <span className="nav-count">{count}</span>}
            </button>
          ))}
        </nav>

        <div className="workspace-label nav-section-label">INTELLIGENCE</div>
        <nav className="primary-nav" aria-label="Intelligence navigation">
          <button className={`nav-item ${page === 'intel' ? 'active' : ''}`} onClick={() => navigate('intel')}>
            <Target size={18} /><span>Threat intelligence</span>
          </button>
          <button className={`nav-item ${page === 'activity' ? 'active' : ''}`} onClick={() => navigate('activity')}>
            <Radio size={18} /><span>Event stream</span>
          </button>
        </nav>

        <div className="sidebar-spacer" />
        <div className="sensor-card">
          <div className="sensor-heading"><span className="pulse-dot" /> PLATFORM STATUS</div>
          <div className="sensor-status">API connection</div>
          <div className="sensor-description">
            {error ? 'Connection needs attention' : loading ? 'Checking service…' : 'Dashboard data loaded'}
          </div>
          <button className="sensor-refresh" onClick={() => loadData(true)} disabled={refreshing}>
            <RefreshCw size={13} /> Refresh connection
          </button>
        </div>
        <div className="sidebar-footer">
          <span className="footer-status-dot" />
          <span>MORPHEUS</span>
          <span className="footer-version">v1.1.0</span>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div className="topbar-left">
            <button className="icon-button mobile-menu" onClick={() => setMobileNavOpen(true)} aria-label="Open menu"><Menu size={20} /></button>
            <div className="breadcrumbs"><span>Workspace</span><span className="breadcrumb-slash">/</span><strong>{currentPageTitle}</strong></div>
          </div>
          <div className="topbar-actions">
            <span className="environment-pill"><span className="pulse-dot" /> LOCAL ENVIRONMENT</span>
            <button className="icon-button refresh-button" onClick={() => loadData(true)} disabled={refreshing} aria-label="Refresh dashboard" title="Refresh dashboard">
              <RefreshCw size={17} className={refreshing ? 'spin' : ''} />
            </button>
            <div className="user-avatar" title="Local analyst">A</div>
          </div>
        </header>

        <div className="page-content">
          {error && (
            <div className="error-banner" role="alert">
              <AlertTriangle size={18} />
              <div><strong>API connection issue</strong><span>{error}</span></div>
              <button className="icon-button" onClick={() => setError('')} aria-label="Dismiss error"><X size={16} /></button>
            </div>
          )}

          {notice && <div className="success-banner"><CheckCircle2 size={17} />{notice}<button className="icon-button" onClick={() => setNotice('')} aria-label="Dismiss message"><X size={15} /></button></div>}

          {page === 'overview' && (
            <>
              <div className="welcome-row">
                <div>
                  <div className="eyebrow"><span className="live-indicator" /> SECURITY OPERATIONS CENTER</div>
                  <h1>Threat overview<span className="title-period">.</span></h1>
                  <p className="welcome-description">Monitor detections, investigate suspicious sessions, and manage incidents.</p>
                </div>
                <button className="button-secondary" onClick={() => loadData(true)} disabled={refreshing}>
                  <RefreshCw size={15} className={refreshing ? 'spin' : ''} /> Refresh data
                </button>
              </div>

              <div className="metrics-grid">
                <MetricCard title="Analyzed sessions" value={loading ? '—' : totalSessions} subtitle="Intelligence assessments" icon={Eye} tone="tone-blue" trend />
                <MetricCard title="Total alerts" value={loading ? '—' : totalAlerts} subtitle="Recorded detections" icon={Bell} tone="tone-purple" />
                <MetricCard title="High priority" value={loading ? '—' : criticalCount} subtitle="High + critical alerts" icon={AlertTriangle} tone="tone-red" />
                <MetricCard title="Active incidents" value={loading ? '—' : activeIncidents} subtitle={`${totalIncidents} total tracked`} icon={ShieldAlert} tone="tone-amber" />
              </div>

              <div className="overview-grid">
                <section className="panel severity-panel">
                  <SectionTitle eyebrow="DETECTION ANALYTICS" title="Alert severity" description="Distribution across recorded alerts" />
                  <div className="severity-total">
                    <div><strong>{severityTotal}</strong><span>total classified alerts</span></div>
                    <span className="severity-total-icon"><ShieldCheck size={21} /></span>
                  </div>
                  <div className="severity-bars">
                    {[
                      { key: 'critical', label: 'Critical', color: 'bar-critical' },
                      { key: 'high', label: 'High', color: 'bar-high' },
                      { key: 'medium', label: 'Medium', color: 'bar-medium' },
                      { key: 'low', label: 'Low', color: 'bar-low' },
                    ].map((item) => {
                      const count = severityCounts[item.key] || 0
                      const width = severityTotal ? (count / severityTotal) * 100 : 0
                      return (
                        <div className="severity-row" key={item.key}>
                          <div className="severity-row-label"><span className={`severity-dot ${item.color}`} />{item.label}</div>
                          <div className="severity-track"><div className={`severity-fill ${item.color}`} style={{ width: `${width}%` }} /></div>
                          <strong>{count}</strong>
                        </div>
                      )
                    })}
                  </div>
                  <div className="panel-footnote"><span className="footnote-dot" /> Based on stored alert events</div>
                </section>

                <section className="panel incident-summary-panel">
                  <SectionTitle eyebrow="SESSION INTELLIGENCE" title="Analyzed severity" description="Risk levels across analyzed sessions" action={<button className="text-button" onClick={() => navigate('sessions')}>View sessions <ExternalLink size={13} /></button>} />
                  <div className="severity-bars" style={{ marginTop: 22 }}>
                    {SEVERITIES.map((severity) => {
                      const count = sessionSeverityCounts[severity] ?? sessions.filter((event) => getRisk(event).severity === severity).length
                      const sessionTotal = Object.values(sessionSeverityCounts).reduce((sum, value) => sum + (Number(value) || 0), 0) || sessions.length
                      const width = sessionTotal ? (count / sessionTotal) * 100 : 0
                      return (
                        <div className="severity-row" key={severity}>
                          <div className="severity-row-label"><span className={`severity-dot bar-${severity}`} />{severity[0].toUpperCase() + severity.slice(1)}</div>
                          <div className="severity-track"><div className={`severity-fill bar-${severity}`} style={{ width: `${width}%` }} /></div>
                          <strong>{count}</strong>
                        </div>
                      )
                    })}
                  </div>
                  <div className="panel-footnote"><span className="footnote-dot" /> Sessions are assessed independently of alert thresholds</div>
                </section>
              </div>

              <section className="panel alerts-panel">
                <SectionTitle eyebrow="INTELLIGENCE PIPELINE" title="Recent analyzed sessions" description="Sessions with completed risk assessments, including sessions that did not trigger alerts" action={<button className="button-secondary compact" onClick={() => navigate('sessions')}>All sessions <ArrowUpRight size={14} /></button>} />
                <SessionTable sessions={sessions.slice(0, 5)} loading={loading} compact onSelect={openSession} />
              </section>

              <section className="panel alerts-panel" style={{ marginTop: 18 }}>
                <SectionTitle eyebrow="LIVE TRIAGE" title="Recent alerts" description="Latest persisted detections from MORPHEUS" action={<button className="button-secondary compact" onClick={() => navigate('alerts')}>All alerts <ArrowUpRight size={14} /></button>} />
                <AlertTable alerts={alerts.slice(0, 5)} loading={loading} onSelect={(alert) => { setPage('alerts'); setSearch(String(getAlertId(alert))) }} />
              </section>

              <div className="bottom-note"><ShieldCheck size={15} /><span>Session intelligence and alerts are read from the configured MORPHEUS event store.</span><span className="bottom-note-right">LOCAL · DEFENSIVE MONITORING</span></div>
            </>
          )}

          {page === 'sessions' && (
            <>
              <SectionTitle eyebrow="SESSION INVESTIGATION" title="Analyzed sessions" description="Inspect SSH activity, risk assessments, behavioral fingerprints, and MITRE ATT&CK mappings." action={<button className="button-secondary" onClick={() => loadData(true)} disabled={refreshing}><RefreshCw size={15} className={refreshing ? 'spin' : ''} /> Refresh</button>} />
              <div className="metrics-grid">
                <MetricCard title="Total analyzed" value={sessions.length} subtitle="Stored intelligence analyses" icon={Eye} tone="tone-blue" />
                <MetricCard title="High / critical" value={sessions.filter((event) => ['high', 'critical'].includes(getRisk(event).severity)).length} subtitle="Sessions needing attention" icon={AlertTriangle} tone="tone-red" />
                <MetricCard title="Successful logins" value={sessions.filter((event) => getSessionInfo(event).authentication_success === true).length} subtitle="Sessions with successful authentication" icon={UserRound} tone="tone-purple" />
                <MetricCard title="Mapped techniques" value={new Set(sessions.flatMap((event) => (getSessionData(event).mitre_techniques || []).map((item) => item.technique_id).filter(Boolean))).size} subtitle="Distinct MITRE ATT&CK IDs" icon={Crosshair} tone="tone-amber" />
              </div>

              <div className="filter-toolbar">
                <div className="search-box"><Search size={16} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search session, IP, user, command, technique…" /></div>
                <div className="filter-select"><Filter size={15} /><select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)} aria-label="Filter sessions by severity"><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></div>
                <span className="result-count">{visibleSessions.length} results</span>
              </div>

              <section className="panel table-panel">
                <SessionTable sessions={visibleSessions} loading={loading} onSelect={openSession} />
              </section>
              <div className="bottom-note"><ShieldCheck size={15} /><span>Risk scores are the recorded results of the MORPHEUS intelligence pipeline.</span></div>
            </>
          )}

          {page === 'alerts' && (
            <>
              <SectionTitle eyebrow="DETECTION MANAGEMENT" title="Security alerts" description="Search and filter alerts generated by the detection pipeline." action={<button className="button-secondary" onClick={() => loadData(true)}><RefreshCw size={15} /> Refresh</button>} />
              <div className="filter-toolbar">
                <div className="search-box"><Search size={16} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search alert, IP, session…" /></div>
                <div className="filter-select"><Filter size={15} /><select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)} aria-label="Filter by severity"><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></div>
                <span className="result-count">{visibleAlerts.length} results</span>
              </div>
              <section className="panel table-panel">
                <AlertTable alerts={visibleAlerts} loading={loading} />
              </section>
            </>
          )}

          {page === 'incidents' && (
            <>
              <SectionTitle eyebrow="RESPONSE WORKFLOW" title="Incident management" description="Track investigations and update the lifecycle status of each case." action={<button className="button-secondary" onClick={() => loadData(true)}><RefreshCw size={15} /> Refresh</button>} />
              <div className="filter-toolbar">
                <div className="search-box"><Search size={16} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search incident ID or alert…" /></div>
                <div className="filter-select"><Filter size={15} /><select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)} aria-label="Filter by status"><option value="all">All statuses</option>{STATUSES.map((status) => <option key={status} value={status}>{status}</option>)}</select></div>
                <span className="result-count">{visibleIncidents.length} results</span>
              </div>
              <section className="panel table-panel">
                {loading ? <div className="loading-state"><LoaderCircle className="spin" size={22} /> Loading incidents…</div> : visibleIncidents.length === 0 ? <EmptyState icon={ShieldCheck} title="No incidents found" message="Try a different filter or wait for alert events to be recorded." /> : (
                  <div className="table-scroll"><table><thead><tr><th>INCIDENT</th><th>RELATED ALERT</th><th>STATUS</th><th>LAST UPDATED</th><th /></tr></thead><tbody>
                    {visibleIncidents.map((incident, index) => (
                      <tr key={`${getIncidentId(incident)}-${index}`}>
                        <td><div className="table-primary">{getIncidentId(incident)}</div><div className="table-secondary">{incident.title || 'Security incident'}</div></td>
                        <td><span className="mono">{shortId(incident.alert_id || '—')}</span></td>
                        <td><StatusBadge status={incident.status} /></td>
                        <td>{formatDate(incident.updated_at || incident.timestamp || incident.created_at)}</td>
                        <td><button className="row-action" onClick={() => setSelectedIncident(incident)}>Manage <ArrowUpRight size={14} /></button></td>
                      </tr>
                    ))}
                  </tbody></table></div>
                )}
              </section>
            </>
          )}

          {(page === 'intel' || page === 'activity') && (
            <div className="coming-soon-panel panel">
              {(() => {
                const item = comingSoon[page]
                const Icon = item.icon
                return <>
                  <span className="coming-icon"><Icon size={28} /></span>
                  <span className="coming-tag">{item.tag}</span>
                  <h1>{item.title}<span className="title-period">.</span></h1>
                  <p>{item.description}</p>
                  <div className="coming-divider" />
                  <div className="coming-note"><Clock3 size={15} /> Planned for a future MORPHEUS milestone</div>
                  <button className="button-secondary" onClick={() => navigate('overview')}>Back to overview</button>
                </>
              })()}
            </div>
          )}
        </div>

        <footer className="main-footer">
          <span>© MORPHEUS · Security telemetry & incident response</span>
          <span><span className="footer-status-dot" /> API-backed dashboard</span>
        </footer>
      </main>

      {selectedIncident && (
        <div className="modal-scrim" onMouseDown={(event) => { if (event.target === event.currentTarget) setSelectedIncident(null) }}>
          <section className="incident-modal" role="dialog" aria-modal="true" aria-labelledby="incident-modal-title">
            <div className="modal-header">
              <div><div className="eyebrow">INCIDENT WORKFLOW</div><h2 id="incident-modal-title">Manage incident</h2></div>
              <button className="icon-button" onClick={() => setSelectedIncident(null)} aria-label="Close dialog"><X size={19} /></button>
            </div>
            <div className="modal-incident-id">{getIncidentId(selectedIncident)}</div>
            <div className="modal-current-status"><span>Current status</span><StatusBadge status={selectedIncident.status} /></div>
            <label className="modal-label" htmlFor="incident-status">Change status</label>
            <div className="modal-status-options">
              {STATUSES.map((status) => (
                <button key={status} className={`modal-status-option ${selectedIncident.status === status ? 'selected' : ''}`} onClick={() => setSelectedIncident({ ...selectedIncident, pendingStatus: status })}>
                  <span className={`status-radio ${selectedIncident.pendingStatus === status || (!selectedIncident.pendingStatus && selectedIncident.status === status) ? 'checked' : ''}`} />
                  <span>{status}</span>
                </button>
              ))}
            </div>
            <p className="modal-help">The change will be recorded in the incident status history.</p>
            <div className="modal-actions">
              <button className="button-secondary" onClick={() => setSelectedIncident(null)}>Cancel</button>
              <button className="button-primary" disabled={updatingIncident || !(selectedIncident.pendingStatus || selectedIncident.status)} onClick={() => changeIncidentStatus(selectedIncident, selectedIncident.pendingStatus || selectedIncident.status)}>
                {updatingIncident ? <LoaderCircle size={15} className="spin" /> : <CheckCircle2 size={15} />} Save status
              </button>
            </div>
          </section>
        </div>
      )}

      {selectedSession && <SessionDetails event={selectedSession} onClose={() => setSelectedSession(null)} />}
    </div>
  )
}

function AlertTable({ alerts, loading, onSelect }) {
  if (loading) return <div className="loading-state"><LoaderCircle className="spin" size={22} /> Loading alert data…</div>
  if (!alerts.length) return <EmptyState icon={ShieldCheck} title="No alerts to display" message="Alerts will appear here after MORPHEUS records qualifying detections." />

  return (
    <div className="table-scroll">
      <table>
        <thead><tr><th>ALERT</th><th>SEVERITY</th><th>SOURCE IP</th><th>SESSION</th><th>TIME</th>{onSelect && <th />}</tr></thead>
        <tbody>
          {alerts.map((alert, index) => {
            const data = getAlertData(alert)
            return (
              <tr key={`${getAlertId(alert)}-${index}`}>
                <td><div className="alert-id-cell"><span className="alert-row-icon"><AlertTriangle size={15} /></span><div><div className="table-primary">{shortId(getAlertId(alert))}</div><div className="table-secondary">{data.summary || data.reason || data.message || 'Detection triggered'}</div></div></div></td>
                <td><SeverityBadge severity={data.severity} /></td>
                <td><span className="mono">{data.source_ip || data.src_ip || '—'}</span></td>
                <td><span className="mono">{shortId(data.session_id || '—')}</span></td>
                <td>{formatDate(alert.timestamp || data.timestamp || data.created_at)}</td>
                {onSelect && <td><button className="row-action" onClick={() => onSelect(alert)}>Inspect <ArrowUpRight size={14} /></button></td>}
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

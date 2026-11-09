import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  Activity, AlertTriangle, ArrowUpRight,
  Bell, CheckCircle2, Clock3, Crosshair,
  ExternalLink, FileSearch, Filter, Fingerprint, LayoutDashboard, LoaderCircle,
  Globe, Menu, Radio, RefreshCw, Search, Shield, ShieldAlert,
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
  const [campaigns, setCampaigns] = useState([])
  const [iocs, setIocs] = useState([])
  const [iocTypeFilter, setIocTypeFilter] = useState('all')
  const [purpleScenarios, setPurpleScenarios] = useState([])
  const [purpleRuns, setPurpleRuns] = useState([])
  const [runningScenario, setRunningScenario] = useState('')
  const [selectedPurpleRun, setSelectedPurpleRun] = useState(null)
  const [purpleError, setPurpleError] = useState('')
  const [httpEvents, setHttpEvents] = useState([])
  const [sensorHealth, setSensorHealth] = useState({
    sensors: [],
    online: 0,
    offline: 0,
    revoked: 0,
  })
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
  const [liveAlert, setLiveAlert] = useState(null)
  const seenAlertEvents = useRef(new Set())

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
        `${API}/campaigns?limit=100`,
        `${API}/iocs?limit=500`,
      ]
      const responses = await Promise.all(endpoints.map((url) => fetch(url)))
      const failed = responses.find((response) => !response.ok)

      if (failed) {
        throw new Error(`API returned HTTP ${failed.status}. Is the MORPHEUS API running?`)
      }

      const [dashboardData, alertsData, incidentsData, sessionsData, campaignsData, iocsData] = await Promise.all(
        responses.map((response) => response.json())
      )

      setDashboard(dashboardData)
      setAlerts(Array.isArray(alertsData.items) ? alertsData.items : [])
      setIncidents(Array.isArray(incidentsData.items) ? incidentsData.items : [])
      setSessions(Array.isArray(sessionsData.items) ? sessionsData.items : [])
      setCampaigns(Array.isArray(campaignsData.items) ? campaignsData.items : [])
      setIocs(Array.isArray(iocsData.items) ? iocsData.items : [])

      // Optional HTTP telemetry must not break the core dashboard.
      try {
        const httpResponse = await fetch(`${API}/http-events?limit=500`)
        if (httpResponse.ok) {
          const httpData = await httpResponse.json()
          setHttpEvents(Array.isArray(httpData.items) ? httpData.items : [])
        } else {
          setHttpEvents([])
        }
      } catch {
        setHttpEvents([])
      }
            // Optional sensor health must not break the core dashboard.
      try {
        const healthResponse = await fetch(`${API}/sensors/health`)
        if (healthResponse.ok) {
          const healthData = await healthResponse.json()
          setSensorHealth({
            sensors: Array.isArray(healthData.sensors) ? healthData.sensors : [],
            online: Number(healthData.online) || 0,
            offline: Number(healthData.offline) || 0,
            revoked: Number(healthData.revoked) || 0,
          })
        }
      } catch {
        // Keep the main dashboard available if sensor health is unavailable.
      }

      // Purple Team is optional: failures must not affect core dashboard data.
      try {
        const [scenarioResponse, runResponse] = await Promise.all([
          fetch(`${API}/purple-team/scenarios`),
          fetch(`${API}/purple-team/runs?limit=50`),
        ])
        if (scenarioResponse.ok) {
          const scenarioData = await scenarioResponse.json()
          setPurpleScenarios(Array.isArray(scenarioData.items) ? scenarioData.items : [])
        }
        if (runResponse.ok) {
          const runData = await runResponse.json()
          setPurpleRuns(Array.isArray(runData.items) ? runData.items : [])
        }
      } catch {
        // Purple Team remains isolated from core dashboard availability.
      }
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

        if (event?.event_type === 'morpheus.alert.created') {
          const eventId = event.event_id || event.data?.alert_id

          if (eventId && !seenAlertEvents.current.has(eventId)) {
            seenAlertEvents.current.add(eventId)

            // Bound memory usage during long-running dashboard sessions.
            if (seenAlertEvents.current.size > 500) {
              const oldest = seenAlertEvents.current.values().next().value
              seenAlertEvents.current.delete(oldest)
            }

            setLiveAlert(event)
          }
        }
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

  async function runPurpleScenario(scenarioId) {
    if (runningScenario) return
    setRunningScenario(scenarioId)
    setPurpleError('')
    setNotice('')

    try {
      const response = await fetch(`${API}/purple-team/runs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario_id: scenarioId }),
      })
      const result = await response.json()
      if (!response.ok) {
        throw new Error(result.detail || `Simulation failed with HTTP ${response.status}`)
      }

      setSelectedPurpleRun(result)
      setPurpleRuns((current) => [
        result,
        ...current.filter((item) => item.run_id !== result.run_id),
      ])
      setNotice(`Purple Team simulation completed: ${result.scenario_name}.`)
    } catch (err) {
      setPurpleError(err.message || 'Unable to run the Purple Team simulation.')
    } finally {
      setRunningScenario('')
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
    { id: 'http', label: 'HTTP deception', icon: Globe, count: httpEvents.length },
  ]

  const comingSoon = {
    intel: {
      icon: Crosshair,
      title: 'Campaign intelligence',
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
            <Target size={18} /><span>Campaign intelligence</span>
          </button>
          <button className={`nav-item ${page === 'iocs' ? 'active' : ''}`} onClick={() => navigate('iocs')}>
            <Fingerprint size={18} /><span>IOC Knowledge Base</span>
            <span className="nav-count">{iocs.length}</span>
          </button>
          <button className={`nav-item ${page === 'purple' ? 'active' : ''}`} onClick={() => navigate('purple')}>
            <Crosshair size={18} /><span>Purple Team Mode</span>
            <span className="nav-count">{purpleScenarios.length}</span>
          </button>
          <button className={`nav-item ${page === 'activity' ? 'active' : ''}`} onClick={() => navigate('activity')}>
            <Radio size={18} /><span>Event stream</span>
          </button>
        </nav>

        <div className="sidebar-spacer" />
                <div className="sensor-card">
          <div className="sensor-heading">
            <span className="pulse-dot" /> SENSOR HEALTH
          </div>

          <div className="sensor-status">
            {sensorHealth.online} online · {sensorHealth.offline} offline
          </div>

          <div className="sensor-description">
            {sensorHealth.sensors.length === 0
              ? 'No registered sensors'
              : `${sensorHealth.sensors.length} registered · ${sensorHealth.revoked} revoked`}
          </div>

          {sensorHealth.sensors.map((sensor) => (
            <div className="sensor-description" key={sensor.sensor_id}>
              <span>{sensor.sensor_id}</span>
              {' — '}
              <span>{sensor.status}</span>
            </div>
          ))}

          <button
            className="sensor-refresh"
            onClick={() => loadData(true)}
            disabled={refreshing}
          >
            <RefreshCw size={13} /> Refresh health
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

          {liveAlert && (() => {
            const data = getAlertData(liveAlert)
            const severity = String(data.severity || 'unknown').toLowerCase()

            return (
              <div className={`live-alert-banner live-alert-${severity}`} role="alert">
               <div className="live-alert-icon">
                <Siren size={21} />
               </div>

               <div className="live-alert-content">
                 <div className="live-alert-heading">
                   <strong>{data.title || 'New security alert detected'}</strong>
                   <span className={`severity-${severity}`}>
                     {severity.toUpperCase()}
                   </span>
                 </div>

                 <p>{data.description || 'MORPHEUS detected suspicious activity.'}</p>

           <div className="live-alert-details">
               <span>Risk: {data.risk_score ?? 'N/A'}/100</span>
                   <span>Source: {data.source_ip || 'Unknown'}</span>
                   <span>Session: {data.session_id || 'Unknown'}</span>
                 </div>

                 <button
                   className="live-alert-open"
                   onClick={() => {
                     setPage('alerts')
                     setSearch(String(getAlertId(liveAlert)))
                     setMobileNavOpen(false)
                     setLiveAlert(null)
                   }}
                  >
                    Investigate alert <ArrowUpRight size={14} />
                  </button>
                </div>

                <button
                  className="icon-button live-alert-dismiss"
                  onClick={() => setLiveAlert(null)}
                  aria-label="Dismiss security alert"
                >
                  <X size={17} />
                </button>
              </div>
            )
          })()}

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

          {page === 'intel' && (
            <>
              <SectionTitle
                eyebrow="CROSS-HONEYPOT INTELLIGENCE"
                title="Campaign intelligence"
                description="Investigate correlated attacker activity reconstructed from persisted analysis events across MORPHEUS sensors."
                action={
                  <button className="button-secondary" onClick={() => loadData(true)} disabled={refreshing}>
                    <RefreshCw size={15} className={refreshing ? 'spin' : ''} /> Refresh
                  </button>
                }
              />

              <div className="metrics-grid">
                <MetricCard
                  title="Correlated campaigns"
                  value={loading ? '—' : campaigns.length}
                  subtitle="Reconstructed attack groups"
                  icon={Target}
                  tone="tone-blue"
                />
                <MetricCard
                  title="Participating sensors"
                  value={loading ? '—' : new Set(campaigns.flatMap((campaign) => Array.isArray(campaign.honeypot_ids) ? campaign.honeypot_ids : [])).size}
                  subtitle="Unique honeypot identities"
                  icon={Radio}
                  tone="tone-purple"
                />
                <MetricCard
                  title="Correlated sessions"
                  value={loading ? '—' : campaigns.reduce((total, campaign) => total + (Array.isArray(campaign.session_ids) ? campaign.session_ids.length : 0), 0)}
                  subtitle="Sessions across campaigns"
                  icon={Eye}
                  tone="tone-amber"
                />
                <MetricCard
                  title="Average confidence"
                  value={loading ? '—' : campaigns.length ? `${Math.round(campaigns.reduce((total, campaign) => total + (Number(campaign.confidence_score) || 0), 0) / campaigns.length)}%` : '—'}
                  subtitle="Campaign correlation confidence"
                  icon={Crosshair}
                  tone="tone-red"
                />
              </div>

              <section className="panel table-panel">
                <SectionTitle
                  eyebrow="CORRELATION RESULTS"
                  title="Detected campaigns"
                  description="Campaigns are reconstructed from stored intelligence analysis events."
                />

                {loading ? (
                  <div className="loading-state">
                    <LoaderCircle className="spin" size={22} /> Loading campaign intelligence…
                  </div>
                ) : campaigns.length === 0 ? (
                  <EmptyState
                    icon={Target}
                    title="No correlated campaigns found"
                    message="Campaigns will appear when persisted session analyses contain sufficient shared evidence to correlate attacker activity across sessions or sensors."
                  />
                ) : (
                  <div className="table-scroll">
                    <table>
                      <thead>
                        <tr>
                          <th>CAMPAIGN</th>
                          <th>CONFIDENCE</th>
                          <th>SENSORS</th>
                          <th>SESSIONS</th>
                          <th>SOURCE IPs</th>
                          <th>INTENTS</th>
                          <th>PHASES</th>
                          <th>LAST SEEN</th>
                        </tr>
                      </thead>
                      <tbody>
                        {campaigns.map((campaign, index) => {
                          const sensors = Array.isArray(campaign.honeypot_ids) ? campaign.honeypot_ids : []
                          const sessionIds = Array.isArray(campaign.session_ids) ? campaign.session_ids : []
                          const sourceIps = Array.isArray(campaign.source_ips) ? campaign.source_ips : []
                          const intents = Array.isArray(campaign.intents) ? campaign.intents : []
                          const phases = Array.isArray(campaign.phases) ? campaign.phases : []
                          const confidence = Math.max(0, Math.min(100, Number(campaign.confidence_score) || 0))

                          return (
                            <tr key={campaign.campaign_id || index}>
                              <td>
                                <div className="table-primary">{shortId(campaign.campaign_id || 'Unknown')}</div>
                                <div className="table-secondary">{formatDate(campaign.first_seen)}</div>
                              </td>
                              <td>
                                <div style={{ display: 'grid', gap: 5, minWidth: 76 }}>
                                  <strong>{confidence}%</strong>
                                  <div className="severity-track">
                                    <div className="severity-fill bar-medium" style={{ width: `${confidence}%` }} />
                                  </div>
                                </div>
                              </td>
                              <td>
                                <div className="table-primary">{sensors.length}</div>
                                <div className="table-secondary">{sensors.join(', ') || '—'}</div>
                              </td>
                              <td>{sessionIds.length}</td>
                              <td><span className="mono">{sourceIps.join(', ') || '—'}</span></td>
                              <td>{intents.join(', ') || '—'}</td>
                              <td>{phases.join(', ') || '—'}</td>
                              <td>{formatDate(campaign.last_seen)}</td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>

              <div className="bottom-note">
                <ShieldCheck size={15} />
                <span>Campaigns are reconstructed from persisted MORPHEUS intelligence events. Confidence is reported on a 0–100 scale.</span>
              </div>
            </>
          )}


          {page === 'iocs' && (
            <>
              <SectionTitle
                eyebrow="THREAT INTELLIGENCE KNOWLEDGE BASE"
                title="IOC Knowledge Base"
                description="Aggregated indicators extracted from persisted MORPHEUS session analyses across honeypots."
                action={
                  <button className="button-secondary" onClick={() => loadData(true)} disabled={refreshing}>
                    <RefreshCw size={15} className={refreshing ? 'spin' : ''} /> Refresh
                  </button>
                }
              />

              <div className="metrics-grid">
                <MetricCard title="Unique indicators" value={iocs.length} subtitle="Aggregated IOC records" icon={Fingerprint} tone="tone-blue" />
                <MetricCard title="IP addresses" value={iocs.filter((item) => item.ioc_type === 'ipv4').length} subtitle="IPv4 indicators" icon={Globe} tone="tone-purple" />
                <MetricCard title="Domains" value={iocs.filter((item) => item.ioc_type === 'domain').length} subtitle="Domain indicators" icon={Target} tone="tone-amber" />
                <MetricCard title="File hashes" value={iocs.filter((item) => ['md5', 'sha256'].includes(item.ioc_type)).length} subtitle="MD5 and SHA-256 indicators" icon={FileSearch} tone="tone-red" />
              </div>

              <div className="filter-toolbar">
                <div className="search-box">
                  <Search size={16} />
                  <input
                    value={search}
                    onChange={(event) => setSearch(event.target.value)}
                    placeholder="Search indicator, session, honeypot, or type…"
                  />
                </div>
                <div className="filter-select">
                  <Filter size={15} />
                  <select value={iocTypeFilter} onChange={(event) => setIocTypeFilter(event.target.value)} aria-label="Filter IOC type">
                    <option value="all">All types</option>
                    <option value="ipv4">IPv4</option>
                    <option value="domain">Domain</option>
                    <option value="md5">MD5</option>
                    <option value="sha256">SHA-256</option>
                  </select>
                </div>
                <span className="result-count">
                  {iocs.filter((item) => {
                    const searchable = [
                      item.value, item.ioc_type, ...(item.sources || []),
                      ...(item.honeypot_ids || []), ...(item.session_ids || []),
                      ...(item.context || []),
                    ].filter(Boolean).join(' ').toLowerCase()
                    return (iocTypeFilter === 'all' || item.ioc_type === iocTypeFilter)
                      && (!search.trim() || searchable.includes(search.trim().toLowerCase()))
                  }).length} results
                </span>
              </div>

              <section className="panel table-panel">
                <SectionTitle eyebrow="OBSERVED INDICATORS" title="Aggregated indicators" description="Occurrences, confidence, source sensors, and supporting context." />
                {loading ? (
                  <div className="loading-state"><LoaderCircle className="spin" size={22} /> Loading indicators…</div>
                ) : iocs.length === 0 ? (
                  <EmptyState icon={Fingerprint} title="No indicators recorded" message="Indicators will appear when MORPHEUS has persisted session analyses containing extractable IOC data." />
                ) : (
                  <div className="table-scroll">
                    <table>
                      <thead>
                        <tr>
                          <th>INDICATOR</th><th>TYPE</th><th>OCCURRENCES</th>
                          <th>CONFIDENCE</th><th>HONEYPOTS</th><th>LAST SEEN</th>
                        </tr>
                      </thead>
                      <tbody>
                        {iocs.filter((item) => {
                          const searchable = [
                            item.value, item.ioc_type, ...(item.sources || []),
                            ...(item.honeypot_ids || []), ...(item.session_ids || []),
                            ...(item.context || []),
                          ].filter(Boolean).join(' ').toLowerCase()
                          return (iocTypeFilter === 'all' || item.ioc_type === iocTypeFilter)
                            && (!search.trim() || searchable.includes(search.trim().toLowerCase()))
                        }).map((item, index) => (
                          <tr key={`${item.ioc_type}-${item.value}-${index}`}>
                            <td>
                              <div className="table-primary mono">{item.value}</div>
                              <div className="table-secondary">
                                {(item.sources || []).join(', ') || 'Source not specified'}
                              </div>
                              {Array.isArray(item.context) && item.context.length > 0 && (
                                <div className="table-secondary">{item.context.slice(0, 2).join(' · ')}</div>
                              )}
                            </td>
                            <td><span className="badge">{item.ioc_type}</span></td>
                            <td>{item.occurrences ?? 0}</td>
                            <td>{`${Math.round((Number(item.confidence) || 0) * 100)}%`}</td>
                            <td>{(item.honeypot_ids || []).join(', ') || '—'}</td>
                            <td>{formatDate(item.last_seen)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>
              <div className="bottom-note">
                <ShieldCheck size={15} />
                <span>Extracted indicators are leads for investigation, not proof that an artifact is malicious. Validate them before blocking or escalation.</span>
              </div>
            </>
          )}

          {page === 'http' && (
            <>
              <SectionTitle
                eyebrow="EXPANDED DECEPTION SERVICES"
                title="HTTP deception"
                description="Inspect HTTP requests captured by the independent MORPHEUS HTTP deception service. This view reads only the dedicated HTTP event store."
                action={
                  <button className="button-secondary" onClick={() => loadData(true)} disabled={refreshing}>
                    <RefreshCw size={15} className={refreshing ? 'spin' : ''} /> Refresh
                  </button>
                }
              />

              <div className="metrics-grid">
                <MetricCard title="HTTP requests" value={httpEvents.length} subtitle="Loaded from HTTP telemetry" icon={Globe} tone="tone-blue" />
                <MetricCard
                  title="Unique source IPs"
                  value={new Set(httpEvents.map((event) => event?.data?.client_ip || event?.data?.source_ip).filter(Boolean)).size}
                  subtitle="Distinct requesting clients" icon={Crosshair} tone="tone-purple"
                />
                <MetricCard
                  title="POST requests"
                  value={httpEvents.filter((event) => String(event?.data?.method || '').toUpperCase() === 'POST').length}
                  subtitle="Requests using POST" icon={Activity} tone="tone-amber"
                />
                <MetricCard
                  title="Error responses"
                  value={httpEvents.filter((event) => Number(event?.data?.response_status ?? event?.data?.status_code) >= 400).length}
                  subtitle="HTTP status 400 and above" icon={AlertTriangle} tone="tone-red"
                />
              </div>

              <div className="filter-toolbar">
                <div className="search-box">
                  <Search size={16} />
                  <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search source IP, method, path, user-agent…" />
                </div>
                <span className="result-count">
                  {httpEvents.filter((event) => {
                    const data = event?.data || {}
                    const searchable = [data.client_ip, data.source_ip, data.method, data.path, data.user_agent, data.content_type, data.response_status, data.status_code].filter(Boolean).join(' ').toLowerCase()
                    return !search.trim() || searchable.includes(search.trim().toLowerCase())
                  }).length} results
                </span>
              </div>

              <section className="panel table-panel">
                <SectionTitle eyebrow="REQUEST TELEMETRY" title="Captured HTTP requests" description="Request bodies, cookies, authorization headers, and passwords are not displayed." />
                {httpEvents.length === 0 ? (
                  <EmptyState icon={Globe} title="No HTTP requests recorded" message="The HTTP deception service may not be running yet, or its dedicated event store has no recorded requests." />
                ) : (
                  <div className="table-scroll">
                    <table>
                      <thead><tr><th>SOURCE IP</th><th>METHOD</th><th>PATH</th><th>STATUS</th><th>RESPONSE TIME</th><th>TIME</th></tr></thead>
                      <tbody>
                        {httpEvents.filter((event) => {
                          const data = event?.data || {}
                          const searchable = [data.client_ip, data.source_ip, data.method, data.path, data.user_agent, data.content_type, data.response_status, data.status_code].filter(Boolean).join(' ').toLowerCase()
                          return !search.trim() || searchable.includes(search.trim().toLowerCase())
                        }).map((event, index) => {
                          const data = event?.data || {}
                          const status = data.response_status ?? data.status_code ?? '—'
                          const duration = data.response_time_ms
                          return (
                            <tr key={event.event_id || `${event.timestamp}-${index}`}>
                              <td><span className="mono">{data.client_ip || data.source_ip || '—'}</span></td>
                              <td><strong>{String(data.method || '—').toUpperCase()}</strong></td>
                              <td><span className="mono">{data.path || '—'}</span></td>
                              <td><span className="mono">{status}</span></td>
                              <td>{duration == null ? '—' : `${Number(duration).toFixed(1)} ms`}</td>
                              <td>{formatDate(event.timestamp)}</td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>
              <div className="bottom-note"><ShieldCheck size={15} /><span>HTTP deception telemetry is isolated from the Cowrie production event store.</span></div>
            </>
          )}


          {page === 'purple' && (
            <>
              <SectionTitle
                eyebrow="CONTROLLED DETECTION VALIDATION"
                title="Purple Team Mode"
                description="Run safe, synthetic command-pattern simulations and compare MITRE ATT&CK techniques with MORPHEUS detection mappings."
                action={
                  <button className="button-secondary" onClick={() => loadData(true)} disabled={refreshing}>
                    <RefreshCw size={15} className={refreshing ? 'spin' : ''} /> Refresh
                  </button>
                }
              />

              {purpleError && (
                <div className="error-banner" role="alert">
                  <AlertTriangle size={18} />
                  <div><strong>Simulation error</strong><span>{purpleError}</span></div>
                  <button className="icon-button" onClick={() => setPurpleError('')} aria-label="Dismiss error"><X size={16} /></button>
                </div>
              )}

              <div className="metrics-grid">
                <MetricCard title="Available scenarios" value={purpleScenarios.length} subtitle="Synthetic test scenarios" icon={Crosshair} tone="tone-blue" />
                <MetricCard title="Simulation runs" value={purpleRuns.length} subtitle="Persisted evaluation results" icon={Activity} tone="tone-purple" />
                <MetricCard title="Latest coverage" value={purpleRuns.length ? `${Number(purpleRuns[0].coverage_percent || 0).toFixed(1)}%` : '—'} subtitle="Expected techniques detected" icon={Target} tone="tone-amber" />
                <MetricCard title="Latest status" value={purpleRuns[0]?.status || '—'} subtitle="Most recent simulation" icon={ShieldCheck} tone="tone-blue" />
              </div>

              <section className="panel" style={{ padding: 21, marginBottom: 18 }}>
                <SectionTitle eyebrow="AVAILABLE TEST CASES" title="Simulation scenarios" description="Choose a scenario to map its synthetic commands against the detection knowledge base." />
                {purpleScenarios.length === 0 ? (
                  <EmptyState icon={Crosshair} title="No scenarios available" message="The Purple Team API may be unavailable. Refresh after confirming the MORPHEUS API is running." />
                ) : (
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(230px, 1fr))', gap: 14 }}>
                    {purpleScenarios.map((scenario) => (
                      <div key={scenario.scenario_id} className="panel" style={{ padding: 16 }}>
                        <div className="eyebrow">{scenario.tactic || 'MITRE ATT&CK'}</div>
                        <h3 style={{ margin: '10px 0 7px', color: '#e6eef9', fontSize: 14 }}>{scenario.name}</h3>
                        <p style={{ color: '#8190a5', fontSize: 11, lineHeight: 1.7, minHeight: 54 }}>{scenario.description}</p>
                        <div className="table-secondary" style={{ margin: '12px 0' }}>
                          {scenario.command_count} synthetic command patterns · {(scenario.expected_techniques || []).length} expected techniques
                        </div>
                        <button
                          className="button-primary"
                          style={{ width: '100%' }}
                          disabled={Boolean(runningScenario)}
                          onClick={() => runPurpleScenario(scenario.scenario_id)}
                        >
                          {runningScenario === scenario.scenario_id
                            ? <><LoaderCircle size={15} className="spin" /> Running…</>
                            : <><Terminal size={15} /> Run simulation</>}
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </section>

              {selectedPurpleRun && (
                <section className="panel" style={{ padding: 21, marginBottom: 18 }}>
                  <SectionTitle
                    eyebrow="SIMULATION RESULT"
                    title={selectedPurpleRun.scenario_name || 'Selected run'}
                    description={`Run ${selectedPurpleRun.run_id || '—'} · ${formatDate(selectedPurpleRun.completed_at)}`}
                  />
                  <div className="metrics-grid">
                    <MetricCard title="Coverage" value={`${Number(selectedPurpleRun.coverage_percent || 0).toFixed(1)}%`} subtitle="Expected techniques detected" icon={Target} tone="tone-blue" />
                    <MetricCard title="Detected" value={(selectedPurpleRun.detected_expected_techniques || []).length} subtitle="Expected techniques matched" icon={CheckCircle2} tone="tone-purple" />
                    <MetricCard title="Missed" value={(selectedPurpleRun.missed_techniques || []).length} subtitle="Expected techniques not matched" icon={AlertTriangle} tone="tone-amber" />
                    <MetricCard title="Commands" value={selectedPurpleRun.command_count ?? 0} subtitle="Synthetic command patterns" icon={Terminal} tone="tone-blue" />
                  </div>
                  <div style={{ marginBottom: 15 }}>
                    <strong style={{ color: '#d6e1f0', fontSize: 12 }}>Detected techniques</strong>
                    {(selectedPurpleRun.detected_techniques || []).length === 0 ? (
                      <p className="table-secondary">No techniques detected.</p>
                    ) : (
                      <ul style={{ color: '#aab9cc', fontSize: 11, lineHeight: 1.9 }}>
                        {selectedPurpleRun.detected_techniques.map((item) => (
                          <li key={item.technique_id}>
                            <span className="mono">{item.technique_id}</span> — {item.technique_name}
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                  <div style={{ marginBottom: 15 }}>
                    <strong style={{ color: '#d6e1f0', fontSize: 12 }}>Missed techniques</strong>
                    <p className="table-secondary">
                      {(selectedPurpleRun.missed_techniques || []).length
                        ? selectedPurpleRun.missed_techniques.join(', ')
                        : 'None'}
                    </p>
                  </div>
                  <strong style={{ color: '#d6e1f0', fontSize: 12 }}>Simulated command patterns (not executed)</strong>
                  <ul style={{ color: '#aab9cc', fontSize: 11, lineHeight: 1.9 }}>
                    {(selectedPurpleRun.simulated_commands || []).map((command, index) => (
                      <li key={`${index}-${command}`}><code>{command}</code></li>
                    ))}
                  </ul>
                </section>
              )}

              <section className="panel table-panel">
                <SectionTitle eyebrow="PERSISTED EVALUATIONS" title="Simulation history" description="Previously completed Purple Team runs." />
                {purpleRuns.length === 0 ? (
                  <EmptyState icon={Activity} title="No simulation runs yet" message="Run one of the scenarios above to create the first evaluation record." />
                ) : (
                  <div className="table-scroll">
                    <table>
                      <thead><tr><th>SCENARIO</th><th>STATUS</th><th>COVERAGE</th><th>TECHNIQUES</th><th>COMPLETED</th><th /></tr></thead>
                      <tbody>
                        {purpleRuns.map((run) => (
                          <tr key={run.run_id}>
                            <td>
                              <div className="table-primary">{run.scenario_name || run.scenario_id}</div>
                              <div className="table-secondary mono">{shortId(run.run_id)}</div>
                            </td>
                            <td><span className="badge">{run.status || 'unknown'}</span></td>
                            <td>{Number(run.coverage_percent || 0).toFixed(1)}%</td>
                            <td>{(run.detected_expected_techniques || []).length}/{(run.expected_techniques || []).length}</td>
                            <td>{formatDate(run.completed_at)}</td>
                            <td>
                              <button className="row-action" onClick={() => setSelectedPurpleRun(run)}>
                                View result <ArrowUpRight size={14} />
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>

              <div className="bottom-note">
                <ShieldCheck size={15} />
                <span>Simulations map predefined synthetic commands only. They do not execute commands, access credentials, or perform network activity.</span>
              </div>
            </>
          )}

          {page === 'activity' && (
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

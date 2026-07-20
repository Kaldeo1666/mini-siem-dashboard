import { useState, useEffect, useRef } from 'react'
import AttackTimeline from './AttackTimeline.jsx'
import { API_HEADERS } from '../App.jsx'
import { severityStyle } from '../theme.js'

const STATUS_COLORS = {
  NEW:           { bg: '#3d1c1c', color: '#f85149' },
  ACKNOWLEDGED:  { bg: '#3d2b00', color: '#e3b341' },
  INVESTIGATING: { bg: '#1f3a5f', color: '#58a6ff' },
  RESOLVED:      { bg: '#1a2f1a', color: '#3fb950' },
}

const NEXT_STATUS = {
  NEW:           'ACKNOWLEDGED',
  ACKNOWLEDGED:  'INVESTIGATING',
  INVESTIGATING: 'RESOLVED',
  RESOLVED:      null,
}

const STATUS_LABELS = {
  NEW:           '🔴 New',
  ACKNOWLEDGED:  '🟡 Acknowledged',
  INVESTIGATING: '🔵 Investigating',
  RESOLVED:      '🟢 Resolved',
}

export default function AlertsPanel({ apiBase }) {
  const [alerts, setAlerts] = useState([])
  const [total, setTotal] = useState(0)
  const [filter, setFilter] = useState('NEW')
  const [loading, setLoading] = useState(false)
  const [timelineAlertId, setTimelineAlertId] = useState(null)
  const wsRef = useRef(null)

  const fetchAlerts = async () => {
    setLoading(true)
    try {
      const params = new URLSearchParams({ page_size: 50 })
      if (filter !== 'ALL') params.set('status', filter)
      const res = await fetch(`${apiBase}/alerts?${params}`, { headers: API_HEADERS })
      const data = await res.json()
      setAlerts(data.alerts || [])
      setTotal(data.total || 0)
    } catch (e) {
      console.error('Failed to fetch alerts:', e)
    } finally {
      setLoading(false)
    }
  }

  // Exports respect the current status filter (the only filter this
  // panel exposes today). Fetches with the auth header, then downloads
  // via a hidden anchor -- a plain link/window.open can't attach
  // custom headers, so the browser can't authenticate a direct navigation.
  const exportAlerts = async (format) => {
    try {
      const params = new URLSearchParams({ format })
      if (filter !== 'ALL') params.set('status', filter)
      const res = await fetch(`${apiBase}/alerts/export?${params}`, { headers: API_HEADERS })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `alerts-export.${format === 'csv' ? 'csv' : 'json'}`
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
    } catch (e) {
      console.error('Export failed:', e)
    }
  }

  // WebSocket connection for real-time alerts
  useEffect(() => {
    const wsUrl = apiBase.replace('http', 'ws') + '/ws/alerts'
    const ws = new WebSocket(wsUrl)
    wsRef.current = ws

    ws.onmessage = (event) => {
      const newAlert = JSON.parse(event.data)
      // Add new alert to top of list if filter matches
      if (filter === 'ALL' || filter === 'NEW') {
        setAlerts(prev => [newAlert, ...prev.slice(0, 49)])
        setTotal(prev => prev + 1)
      }
    }

    ws.onerror = () => console.log('[WS] Alert WebSocket error')
    ws.onclose = () => console.log('[WS] Alert WebSocket closed')

    return () => ws.close()
  }, [apiBase, filter])

  useEffect(() => { fetchAlerts() }, [filter])

  // Auto refresh every 30 seconds
  useEffect(() => {
    const interval = setInterval(fetchAlerts, 30_000)
    return () => clearInterval(interval)
  }, [filter])

  const transitionStatus = async (alertId, newStatus) => {
    try {
      await fetch(`${apiBase}/alerts/${alertId}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', ...API_HEADERS },
        body: JSON.stringify({ status: newStatus }),
      })
      fetchAlerts()
    } catch (e) {
      console.error('Failed to update alert:', e)
    }
  }

  const s = {
    card: {
      background: '#161b22', border: '1px solid #30363d',
      borderRadius: '10px', overflow: 'hidden', marginBottom: '24px',
    },
    header: {
      padding: '14px 16px', borderBottom: '1px solid #30363d',
      display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap',
    },
    title: { color: '#e6edf3', fontWeight: 700, fontSize: '15px' },
    filterBtn: (active) => ({
      background: active ? '#1f6feb' : '#21262d',
      border: `1px solid ${active ? '#58a6ff' : '#30363d'}`,
      color: active ? '#fff' : '#8b949e',
      borderRadius: '6px', padding: '5px 12px',
      fontSize: '12px', cursor: 'pointer',
    }),
    alertRow: {
      padding: '14px 16px', borderBottom: '1px solid #21262d',
      display: 'flex', alignItems: 'flex-start', gap: '12px',
    },
    badge: (colors) => ({
      background: colors.bg, color: colors.color,
      border: `1px solid ${colors.color}`,
      borderRadius: '4px', padding: '2px 8px',
      fontSize: '11px', fontWeight: 700, whiteSpace: 'nowrap',
    }),
    actionBtn: {
      background: '#21262d', border: '1px solid #30363d',
      color: '#8b949e', borderRadius: '6px',
      padding: '4px 10px', fontSize: '11px', cursor: 'pointer',
    },
    empty: {
      padding: '40px', textAlign: 'center',
      color: '#484f58', fontSize: '14px',
    },
  }

  return (
    <div id="tour-alerts-panel" style={s.card}>
      <div style={s.header}>
        <span style={s.title}>🚨 Alerts ({total})</span>
        {['ALL', 'NEW', 'ACKNOWLEDGED', 'INVESTIGATING', 'RESOLVED'].map(f => (
          <button key={f} style={s.filterBtn(filter === f)}
            onClick={() => setFilter(f)}>
            {f}
          </button>
        ))}
        <button style={s.filterBtn(false)}
          onClick={() => exportAlerts('csv')}>⬇ Export CSV</button>
        <button style={s.filterBtn(false)}
          onClick={() => exportAlerts('json')}>⬇ Export JSON</button>
        <button style={{ ...s.filterBtn(false), marginLeft: 'auto' }}
          onClick={fetchAlerts}>↻ Refresh</button>
      </div>

      {alerts.length === 0 ? (
        <div style={s.empty}>
          {loading ? '⏳ Loading...' : '✅ No alerts matching this filter'}
        </div>
      ) : (
        alerts.map(alert => {
          const sevColors = severityStyle(alert.severity)
          const statColors = STATUS_COLORS[alert.status] || STATUS_COLORS.NEW
          const nextStatus = NEXT_STATUS[alert.status]

          return (
            <div key={alert.id} style={s.alertRow}>
              {/* Severity badge — color AND icon, not color alone (accessibility) */}
              <span style={s.badge(sevColors)}>{sevColors.icon} {alert.severity}</span>

              {/* Main content */}
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                  <span style={{ color: '#e6edf3', fontWeight: 600, fontSize: '13px' }}>
                    {alert.rule_name}
                  </span>
                  <span style={s.badge({ ...statColors, border: statColors.color })}>
                    {STATUS_LABELS[alert.status]}
                  </span>
                  {alert.mitre_technique_id && (
  <a
    href={`https://attack.mitre.org/techniques/${alert.mitre_technique_id}/`}
    target="_blank"
    rel="noreferrer"
    style={{
      background: '#0d1117',
      color: '#79c0ff',
      border: '1px solid #1f6feb',
      borderRadius: '4px',
      padding: '2px 8px',
      fontSize: '11px',
      fontWeight: 700,
      textDecoration: 'none',
      fontFamily: 'monospace',
      whiteSpace: 'nowrap',
    }}
  >
    MITRE {alert.mitre_technique_id} ↗
  </a>
)}
                </div>
                <div style={{ color: '#8b949e', fontSize: '12px', marginTop: '4px' }}>
                  {alert.source_ip && <span>IP: {alert.source_ip} · </span>}
                  {alert.source_type && <span>Source: {alert.source_type} · </span>}
                  <span>Triggered: {new Date(alert.triggered_at).toLocaleString()}</span>
                  {alert.description && (
                    <div style={{ marginTop: '4px', color: '#6e7681' }}>{alert.description}</div>
                  )}
                </div>
                {alert.notes && (
                  <div style={{ color: '#8b949e', fontSize: '11px', marginTop: '4px',
                    fontStyle: 'italic' }}>
                    📝 {alert.notes}
                  </div>
                )}
              </div>

              {/* Action button */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                {alert.is_correlation && (
                  <button style={s.actionBtn} onClick={() => setTimelineAlertId(alert.id)}>
                    ⚔️ Timeline
                  </button>
                )}
                {nextStatus && (
                  <button style={s.actionBtn}
                    onClick={() => transitionStatus(alert.id, nextStatus)}>
                    → {nextStatus}
                  </button>
                )}
              </div>
            </div>
          )
        })
      )}

      {timelineAlertId && (
        <AttackTimeline
          apiBase={apiBase}
          alertId={timelineAlertId}
          onClose={() => setTimelineAlertId(null)}
        />
      )}
    </div>
  )
}
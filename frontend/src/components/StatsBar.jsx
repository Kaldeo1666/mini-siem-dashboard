import { useState, useEffect } from 'react'
import { API_HEADERS } from '../App.jsx'
import { COLORS } from '../theme.js'

// Log levels don't map 1:1 to alert severities, so this stays a local
// mapping rather than reusing COLORS.severity — but pulls the same
// underlying palette for visual consistency across the dashboard.
const LEVEL_COLORS = {
  DEBUG:    { bg: COLORS.bgInset, text: COLORS.textSecondary, border: COLORS.border, icon: '⚪' },
  INFO:     { bg: '#0d1f3a', text: COLORS.severity.LOW.color, border: COLORS.severity.LOW.color, icon: '🔵' },
  WARN:     { bg: COLORS.severity.MEDIUM.bg, text: COLORS.severity.MEDIUM.color, border: COLORS.severity.MEDIUM.color, icon: '🟡' },
  ERROR:    { bg: COLORS.severity.HIGH.bg, text: COLORS.severity.HIGH.color, border: COLORS.severity.HIGH.color, icon: '🟠' },
  CRITICAL: { bg: COLORS.severity.CRITICAL.bg, text: COLORS.severity.CRITICAL.color, border: COLORS.severity.CRITICAL.color, icon: '🔴' },
}

const SOURCE_ICONS = {
  apache:        '🌐',
  nginx:         '🌐',
  syslog:        '🖥️',
  json:          '📋',
  firewall:      '🔥',
  windows_event: '🪟',
}

export default function StatsBar({ apiBase }) {
  const [stats, setStats] = useState(null)

  useEffect(() => {
    const load = async () => {
      try {
        const res = await fetch(`${apiBase}/logs/stats`, { headers: API_HEADERS })
        if (res.ok) setStats(await res.json())
      } catch {}
    }
    load()
    const interval = setInterval(load, 15_000)
    return () => clearInterval(interval)
  }, [apiBase])

  if (!stats) return null

  return (
    <div id="tour-stats-bar" style={{ marginBottom: '20px' }}>
      {/* Level counts */}
      <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', marginBottom: '12px' }}>
        {['CRITICAL', 'ERROR', 'WARN', 'INFO', 'DEBUG'].map(level => {
          const found = stats.by_level.find(l => l.level === level)
          const count = found ? found.count : 0
          const c = LEVEL_COLORS[level]
          return (
            <div key={level} style={{
              background: c.bg,
              border: `1px solid ${c.border}`,
              borderRadius: '8px',
              padding: '10px 18px',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              minWidth: '90px',
            }}>
              <span style={{ fontSize: '22px', fontWeight: 700, color: c.text }}>
                {count.toLocaleString()}
              </span>
              <span style={{ fontSize: '11px', color: c.text, opacity: 0.8, marginTop: '2px' }}>
                {c.icon} {level}
              </span>
            </div>
          )
        })}

        {/* Divider + source type pills */}
        <div style={{
          width: '1px', background: '#30363d', margin: '0 4px', alignSelf: 'stretch'
        }} />

        {stats.by_source_type.map(s => (
          <div key={s.source_type} style={{
            background: '#161b22',
            border: '1px solid #30363d',
            borderRadius: '8px',
            padding: '10px 18px',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            minWidth: '90px',
          }}>
            <span style={{ fontSize: '22px', fontWeight: 700, color: '#e6edf3' }}>
              {s.count.toLocaleString()}
            </span>
            <span style={{ fontSize: '11px', color: '#8b949e', marginTop: '2px' }}>
              {SOURCE_ICONS[s.source_type] || '📄'} {s.source_type}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

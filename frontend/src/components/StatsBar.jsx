import { useState, useEffect } from 'react'

const LEVEL_COLORS = {
  DEBUG:    { bg: '#21262d', text: '#8b949e', border: '#30363d' },
  INFO:     { bg: '#1f3a5f', text: '#58a6ff', border: '#1f6feb' },
  WARN:     { bg: '#3d2b00', text: '#e3b341', border: '#9e6a03' },
  ERROR:    { bg: '#3d1c1c', text: '#f85149', border: '#da3633' },
  CRITICAL: { bg: '#4a0e0e', text: '#ff7b72', border: '#f85149' },
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
        const res = await fetch(`${apiBase}/logs/stats`)
        if (res.ok) setStats(await res.json())
      } catch {}
    }
    load()
    const interval = setInterval(load, 15_000)
    return () => clearInterval(interval)
  }, [apiBase])

  if (!stats) return null

  return (
    <div style={{ marginBottom: '20px' }}>
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
                {level}
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

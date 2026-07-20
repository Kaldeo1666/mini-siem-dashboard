import { useState, useEffect } from 'react'
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid,
  Tooltip, Legend, ResponsiveContainer,
} from 'recharts'
import { API_HEADERS } from '../App.jsx'

const SOURCE_COLORS = {
  apache:        '#58a6ff',
  nginx:         '#58a6ff',
  syslog:        '#e3b341',
  json:          '#3fb950',
  firewall:      '#f85149',
  windows_event: '#a371f7',
}

function fmtMinute(iso) {
  const d = new Date(iso)
  return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', hour12: false })
}

export default function EventsChart({ apiBase }) {
  const [chartData, setChartData] = useState([])
  const [sourceTypes, setSourceTypes] = useState([])
  const [loading, setLoading] = useState(true)

  const fetchData = async () => {
    try {
      const res = await fetch(`${apiBase}/logs/events-per-minute?minutes=60`, { headers: API_HEADERS })
      if (!res.ok) return
      const { data } = await res.json()

      const byMinute = {}
      const types = new Set()
      for (const row of data) {
        types.add(row.source_type)
        if (!byMinute[row.minute]) byMinute[row.minute] = { minute: row.minute }
        byMinute[row.minute][row.source_type] = row.count
      }

      const rows = Object.values(byMinute).sort((a, b) => a.minute.localeCompare(b.minute))
      setChartData(rows)
      setSourceTypes([...types])
    } catch (e) {
      console.error('Failed to fetch events/minute:', e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 5_000)
    return () => clearInterval(interval)
  }, [apiBase])

  const s = {
    card: {
      background: '#161b22', border: '1px solid #30363d',
      borderRadius: '10px', padding: '16px', marginBottom: '24px',
    },
    title: { color: '#e6edf3', fontWeight: 700, fontSize: '15px', marginBottom: '12px' },
    empty: { padding: '40px', textAlign: 'center', color: '#484f58', fontSize: '14px' },
  }

  return (
    <div id="tour-events-chart" style={s.card}>
      <div style={s.title}>📈 Events / Minute (last 60 min)</div>
      {chartData.length === 0 ? (
        <div style={s.empty}>
          {loading ? '⏳ Loading…' : '📭 No recent events to chart yet.'}
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={260}>
          <LineChart data={chartData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
            <XAxis dataKey="minute" tickFormatter={fmtMinute} stroke="#8b949e" fontSize={11} />
            <YAxis stroke="#8b949e" fontSize={11} allowDecimals={false} />
            <Tooltip
              labelFormatter={fmtMinute}
              contentStyle={{ background: '#161b22', border: '1px solid #30363d', borderRadius: '6px' }}
              labelStyle={{ color: '#e6edf3' }}
            />
            <Legend wrapperStyle={{ fontSize: '12px', color: '#8b949e' }} />
            {sourceTypes.map(type => (
              <Line
                key={type}
                type="monotone"
                dataKey={type}
                stroke={SOURCE_COLORS[type] || '#8b949e'}
                strokeWidth={2}
                dot={false}
                connectNulls
              />
            ))}
          </LineChart>
        </ResponsiveContainer>
      )}
    </div>
  )
}
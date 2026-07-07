import { useState, useEffect } from 'react'

function flagEmoji(countryCode) {
  if (!countryCode || countryCode.length !== 2) return '🏳️'
  const codePoints = [...countryCode.toUpperCase()].map(c => 127397 + c.charCodeAt(0))
  return String.fromCodePoint(...codePoints)
}

export default function TopIPsTable({ apiBase }) {
  const [topIps, setTopIps] = useState([])
  const [loading, setLoading] = useState(true)

  const fetchData = async () => {
    try {
      const res = await fetch(`${apiBase}/logs/top-ips?hours=1&limit=10`)
      if (!res.ok) return
      const { top_ips } = await res.json()
      setTopIps(top_ips)
    } catch (e) {
      console.error('Failed to fetch top IPs:', e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 15_000)
    return () => clearInterval(interval)
  }, [apiBase])

  const s = {
    card: {
      background: '#161b22', border: '1px solid #30363d',
      borderRadius: '10px', overflow: 'hidden', marginBottom: '24px',
    },
    title: {
      color: '#e6edf3', fontWeight: 700, fontSize: '15px',
      padding: '14px 16px', borderBottom: '1px solid #30363d',
    },
    table: { width: '100%', borderCollapse: 'collapse', fontSize: '13px' },
    th: {
      background: '#0d1117', color: '#8b949e', fontWeight: 600,
      padding: '8px 16px', textAlign: 'left', borderBottom: '1px solid #30363d',
    },
    td: { padding: '9px 16px', borderBottom: '1px solid #21262d', color: '#c9d1d9' },
    empty: { padding: '40px', textAlign: 'center', color: '#484f58', fontSize: '14px' },
  }

  return (
    <div style={s.card}>
      <div style={s.title}>🌍 Top Source IPs (last hour)</div>
      {topIps.length === 0 ? (
        <div style={s.empty}>
          {loading ? '⏳ Loading…' : '📭 No traffic in the last hour.'}
        </div>
      ) : (
        <table style={s.table}>
          <thead>
            <tr>
              <th style={s.th}>#</th>
              <th style={s.th}>Country</th>
              <th style={s.th}>Source IP</th>
              <th style={s.th}>Events</th>
            </tr>
          </thead>
          <tbody>
            {topIps.map((row, i) => (
              <tr key={row.source_ip}>
                <td style={s.td}>{i + 1}</td>
                <td style={s.td}>{flagEmoji(row.country_code)} {row.country_name || 'Unknown'}</td>
                <td style={{ ...s.td, fontFamily: 'monospace', color: '#79c0ff' }}>{row.source_ip}</td>
                <td style={{ ...s.td, fontWeight: 600 }}>{row.count.toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
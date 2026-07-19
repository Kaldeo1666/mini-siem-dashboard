import { useState, useEffect, useCallback } from 'react'
import LogTable from './components/LogTable.jsx'
import AlertsPanel from './components/AlertsPanel.jsx'
import StatsBar from './components/StatsBar.jsx'
import EventsChart from './components/EventsChart.jsx'
import TopIPsTable from './components/TopIPsTable.jsx'
import HuntPage from './components/HuntPage.jsx'
import CasesPage from './components/CasesPage.jsx'
import DemoControls from './components/DemoControls.jsx'

// Base URL for API calls
// Inside Docker, the Vite proxy rewrites /api → http://api:8000
// Outside Docker (local dev), VITE_API_URL is http://localhost:8000
const API_BASE = import.meta.env.VITE_API_URL || '/api'
const API_KEY = import.meta.env.VITE_API_KEY || ''
const API_HEADERS = { 'X-API-Key': API_KEY }

export { API_BASE, API_KEY, API_HEADERS }

import { COLORS } from './theme.js'

const styles = {
  app: {
    minHeight: '100vh',
    background: COLORS.bg,
    color: COLORS.textPrimary,
  },
  nav: {
    background: '#161b22',
    borderBottom: '1px solid #30363d',
    padding: '0 24px',
    display: 'flex',
    alignItems: 'center',
    height: '56px',
    gap: '16px',
  },
  navBrand: {
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    fontWeight: 700,
    fontSize: '18px',
    color: '#58a6ff',
    letterSpacing: '-0.3px',
  },
  navBadge: {
    background: '#21262d',
    border: '1px solid #30363d',
    borderRadius: '999px',
    padding: '2px 10px',
    fontSize: '12px',
    color: '#8b949e',
    marginLeft: 'auto',
  },
  main: {
    padding: '24px',
    maxWidth: '1600px',
    margin: '0 auto',
  },
}

export default function App() {
  const [totalLogs, setTotalLogs] = useState(null)
  const [tab, setTab] = useState('dashboard')

  // Refresh total count every 10 seconds (stretch goal badge)
  const fetchTotal = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/logs/stats`, { headers: API_HEADERS })
      if (res.ok) {
        const data = await res.json()
        setTotalLogs(data.total)
      }
    } catch {
      // API not yet available — silently ignore
    }
  }, [])

  useEffect(() => {
    fetchTotal()
    const interval = setInterval(fetchTotal, 10_000)
    return () => clearInterval(interval)
  }, [fetchTotal])

  return (
    <div style={styles.app}>
      <nav style={styles.nav}>
        <div style={styles.navBrand}>
          {/* Shield icon */}
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#58a6ff" strokeWidth="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
          Mini SIEM
        </div>
        <span style={{ color: '#8b949e', fontSize: '13px' }}>v3 — Live Dashboard & Threat Hunting</span>
        <div style={{ display: 'flex', gap: '8px', marginLeft: '20px' }}>
          <button
            onClick={() => setTab('dashboard')}
            style={{
              background: tab === 'dashboard' ? '#1f6feb' : '#21262d',
              border: `1px solid ${tab === 'dashboard' ? '#58a6ff' : '#30363d'}`,
              color: tab === 'dashboard' ? '#fff' : '#8b949e',
              borderRadius: '6px', padding: '5px 14px', fontSize: '13px', cursor: 'pointer',
            }}>
            📊 Dashboard
          </button>
          <button
            onClick={() => setTab('hunt')}
            style={{
              background: tab === 'hunt' ? '#1f6feb' : '#21262d',
              border: `1px solid ${tab === 'hunt' ? '#58a6ff' : '#30363d'}`,
              color: tab === 'hunt' ? '#fff' : '#8b949e',
              borderRadius: '6px', padding: '5px 14px', fontSize: '13px', cursor: 'pointer',
            }}>
            🔎 Threat Hunting
          </button>
          <button
            onClick={() => setTab('cases')}
            style={{
              background: tab === 'cases' ? '#1f6feb' : '#21262d',
              border: `1px solid ${tab === 'cases' ? '#58a6ff' : '#30363d'}`,
              color: tab === 'cases' ? '#fff' : '#8b949e',
              borderRadius: '6px', padding: '5px 14px', fontSize: '13px', cursor: 'pointer',
            }}>
            📁 Cases
          </button>
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '12px' }}>
          <DemoControls apiBase={API_BASE} />
          {totalLogs !== null && (
            <div style={styles.navBadge}>
              {totalLogs.toLocaleString()} logs ingested
            </div>
          )}
        </div>
      </nav>

      <main style={styles.main}>
        {tab === 'dashboard' ? (
          <>
            <AlertsPanel apiBase={API_BASE} />
            <StatsBar apiBase={API_BASE} />
            <EventsChart apiBase={API_BASE} />
            <TopIPsTable apiBase={API_BASE} />
            <LogTable apiBase={API_BASE} />
          </>
        ) : tab === 'hunt' ? (
          <HuntPage apiBase={API_BASE} />
        ) : (
          <CasesPage apiBase={API_BASE} />
        )}
      </main>
    </div>
  )
}

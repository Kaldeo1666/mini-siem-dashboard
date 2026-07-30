import { useState, useEffect, useRef } from 'react'
import { API_HEADERS } from '../App.jsx'
import { COLORS } from '../theme.js'

const STAGE_LABELS = {
  'Recon': '🔍 Recon — port scanning',
  'Brute Force': '🔨 Brute Force — credential attempts',
  'Exploitation': '💥 Exploitation — admin login',
  'Exfiltration': '📤 Exfiltration — large data transfer',
}

const STAGE_ORDER = ['Recon', 'Brute Force', 'Exploitation', 'Exfiltration']

export default function DemoControls({ apiBase }) {
  const [status, setStatus] = useState(null)
  const [error, setError] = useState(null)
  const pollRef = useRef(null)

  const fetchStatus = async () => {
    try {
      const res = await fetch(`${apiBase}/demo/status`, { headers: API_HEADERS })
      if (res.ok) setStatus(await res.json())
    } catch (e) {
      console.error('Failed to fetch demo status:', e)
    }
  }

  // Poll every 2s while a demo is running (or might just have started),
  // so the progress banner updates without needing a page refresh.
  useEffect(() => {
    fetchStatus()
    pollRef.current = setInterval(fetchStatus, 2000)
    return () => clearInterval(pollRef.current)
  }, [apiBase])

  const runDemo = async () => {
    setError(null)
    try {
      const res = await fetch(`${apiBase}/demo/run`, { method: 'POST', headers: API_HEADERS })
      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        throw new Error(body.detail || `HTTP ${res.status}`)
      }
      fetchStatus()
    } catch (e) {
      setError(e.message)
    }
  }

  const isRunning = status?.running

  const s = {
    button: {
      background: isRunning ? COLORS.severity.MEDIUM.bg : COLORS.severity.HIGH.color,
      border: `1px solid ${isRunning ? COLORS.severity.MEDIUM.color : COLORS.severity.HIGH.color}`,
      color: isRunning ? COLORS.severity.MEDIUM.color : '#1a1206',
      borderRadius: '6px', padding: '5px 14px', fontSize: '13px',
      cursor: isRunning ? 'not-allowed' : 'pointer', fontWeight: 600,
    },
    banner: {
      background: COLORS.bgPanel,
      border: `1px solid ${COLORS.severity.MEDIUM.color}`,
      borderRadius: '8px',
      padding: '14px 20px',
      marginBottom: '24px',
      display: 'flex',
      alignItems: 'center',
      gap: '16px',
      flexWrap: 'wrap',
    },
    stagePill: (state) => ({
      padding: '4px 10px',
      borderRadius: '999px',
      fontSize: '12px',
      fontWeight: 600,
      background: state === 'done' ? '#1a2f1a'
                : state === 'active' ? COLORS.severity.MEDIUM.bg
                : COLORS.bgInset,
      color: state === 'done' ? '#3fb950'
           : state === 'active' ? COLORS.severity.MEDIUM.color
           : COLORS.textMuted,
      border: `1px solid ${
        state === 'done' ? '#3fb950'
        : state === 'active' ? COLORS.severity.MEDIUM.color
        : COLORS.border
      }`,
    }),
  }

  return (
    <>
      <button
        id="tour-run-demo"
        style={s.button}
        onClick={runDemo}
        disabled={isRunning}
        title="Resets demo data (logs, alerts, cases) and runs a live 4-stage attack simulation. Rules, IOCs, and API keys are preserved."
      >
        {isRunning ? '⏳ Demo Running…' : '▶ Run Demo'}
      </button>

      {error && (
        <div style={{ color: COLORS.severity.HIGH.color, fontSize: '12px', marginLeft: '8px' }}>
          ⚠ {error}
        </div>
      )}

      {isRunning && status && (
        <div style={s.banner}>
          <span style={{ color: COLORS.textPrimary, fontWeight: 700, fontSize: '13px' }}>
            🎬 Demo Running
          </span>
          {STAGE_ORDER.map(stage => {
            const state = status.stages_completed.includes(stage)
              ? 'done'
              : status.current_stage === stage
              ? 'active'
              : 'pending'
            return (
              <span key={stage} style={s.stagePill(state)}>
                {state === 'done' ? '✓ ' : state === 'active' ? '● ' : '○ '}
                {STAGE_LABELS[stage]}
              </span>
            )
          })}
        </div>
      )}
    </>
  )
}
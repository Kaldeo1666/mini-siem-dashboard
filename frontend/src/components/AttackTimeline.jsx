import { useState, useEffect } from 'react'

export default function AttackTimeline({ apiBase, alertId, onClose }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [selectedLog, setSelectedLog] = useState(null)

  useEffect(() => {
    const fetchTimeline = async () => {
      try {
        const res = await fetch(`${apiBase}/alerts/${alertId}/timeline`)
        if (!res.ok) {
          const body = await res.json().catch(() => ({}))
          throw new Error(body.detail || `HTTP ${res.status}`)
        }
        setData(await res.json())
      } catch (e) {
        setError(e.message)
      }
    }
    fetchTimeline()
  }, [apiBase, alertId])

  const s = {
    overlay: {
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000,
    },
    modal: {
      background: '#161b22', border: '1px solid #30363d', borderRadius: '10px',
      padding: '24px', maxWidth: '800px', width: '90%', maxHeight: '80vh', overflowY: 'auto',
    },
    header: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' },
    title: { color: '#e6edf3', fontWeight: 700, fontSize: '16px' },
    closeBtn: { background: '#21262d', border: '1px solid #30363d', color: '#8b949e', borderRadius: '6px', padding: '4px 10px', cursor: 'pointer' },
    swimlane: { display: 'flex', alignItems: 'center', gap: '20px', marginBottom: '20px' },
    stage: (color) => ({
      flex: 1, background: '#0d1117', border: `1px solid ${color}`, borderRadius: '8px',
      padding: '14px', cursor: 'pointer',
    }),
    arrow: { color: '#58a6ff', fontSize: '24px' },
    stageLabel: (color) => ({ color, fontWeight: 700, fontSize: '11px', marginBottom: '6px' }),
    field: { color: '#8b949e', fontSize: '12px', marginTop: '4px' },
    rawBox: {
      background: '#0d1117', border: '1px solid #30363d', borderRadius: '6px',
      padding: '12px', marginTop: '16px', fontSize: '12px', fontFamily: 'monospace',
      color: '#c9d1d9', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
    },
  }

  return (
    <div style={s.overlay} onClick={onClose}>
      <div style={s.modal} onClick={e => e.stopPropagation()}>
        <div style={s.header}>
          <span style={s.title}>⚔️ Attack Pattern Timeline</span>
          <button style={s.closeBtn} onClick={onClose}>✕ Close</button>
        </div>

        {error && <div style={{ color: '#f85149', fontSize: '13px' }}>⚠ {error}</div>}

        {data && (
          <>
            <div style={{ color: '#8b949e', fontSize: '13px', marginBottom: '16px' }}>
              {data.alert.rule_name} · {data.alert.source_ip} · MITRE {data.alert.mitre_technique_id}
            </div>

            <div style={s.swimlane}>
              <div style={s.stage('#e3b341')} onClick={() => setSelectedLog(data.stages[0].log)}>
                <div style={s.stageLabel('#e3b341')}>STAGE A — INITIAL EVENT</div>
                <div style={{ color: '#e6edf3', fontWeight: 600 }}>{data.stages[0].log.source_type}</div>
                <div style={s.field}>🕐 {new Date(data.stages[0].log.timestamp).toLocaleString()}</div>
                <div style={s.field}>📍 {data.stages[0].log.source_ip || 'no IP'}</div>
                <div style={s.field}>⚡ {data.stages[0].log.action || data.stages[0].log.message || '—'}</div>
              </div>

              <span style={s.arrow}>→</span>

              <div style={s.stage('#f85149')} onClick={() => setSelectedLog(data.stages[1].log)}>
                <div style={s.stageLabel('#f85149')}>STAGE B — FOLLOW-UP EVENT</div>
                <div style={{ color: '#e6edf3', fontWeight: 600 }}>{data.stages[1].log.source_type}</div>
                <div style={s.field}>🕐 {new Date(data.stages[1].log.timestamp).toLocaleString()}</div>
                <div style={s.field}>📍 {data.stages[1].log.source_ip || 'no IP'}</div>
                <div style={s.field}>⚡ {data.stages[1].log.action || data.stages[1].log.message || '—'}</div>
              </div>
            </div>

            <div style={{ color: '#6e7681', fontSize: '12px' }}>
              Click a stage above to view its raw log entry.
            </div>

            {selectedLog && (
              <div style={s.rawBox}>{selectedLog.raw || '(no raw data captured)'}</div>
            )}
          </>
        )}

        {!data && !error && (
          <div style={{ color: '#484f58', textAlign: 'center', padding: '30px' }}>⏳ Loading…</div>
        )}
      </div>
    </div>
  )
}
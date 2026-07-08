import { useState, useEffect } from 'react'

const FIELDS = ['source_ip', 'source_type', 'level', 'status_code', 'action', 'message', 'source_host', 'user']
const OPERATORS = ['=', '!=', 'contains', '>', '<', 'regex']

export default function HuntPage({ apiBase }) {
  const [conditions, setConditions] = useState([{ field: 'source_ip', operator: '=', value: '' }])
  const [combinator, setCombinator] = useState('AND')
  const [results, setResults] = useState([])
  const [total, setTotal] = useState(0)
  const [huntName, setHuntName] = useState('')
  const [savedHunts, setSavedHunts] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const fetchSavedHunts = async () => {
    try {
      const res = await fetch(`${apiBase}/hunts`)
      if (res.ok) setSavedHunts((await res.json()).hunts)
    } catch (e) { console.error(e) }
  }

  useEffect(() => { fetchSavedHunts() }, [])

  const addCondition = () => setConditions(c => [...c, { field: 'source_ip', operator: '=', value: '' }])
  const removeCondition = (i) => setConditions(c => c.filter((_, idx) => idx !== i))
  const updateCondition = (i, key, value) =>
    setConditions(c => c.map((cond, idx) => idx === i ? { ...cond, [key]: value } : cond))

  const runPreview = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch(`${apiBase}/hunt/preview`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ conditions, combinator, page: 1, page_size: 50 }),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      setResults(data.logs)
      setTotal(data.total)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  const saveHunt = async () => {
    if (!huntName.trim()) return
    await fetch(`${apiBase}/hunts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: huntName, filters: { conditions, combinator, page: 1, page_size: 50 } }),
    })
    setHuntName('')
    fetchSavedHunts()
  }

  const loadHunt = (hunt) => {
    setConditions(hunt.filters.conditions)
    setCombinator(hunt.filters.combinator)
  }

  const deleteHunt = async (id) => {
    await fetch(`${apiBase}/hunts/${id}`, { method: 'DELETE' })
    fetchSavedHunts()
  }

  const createRule = async (id) => {
    const res = await fetch(`${apiBase}/hunts/${id}/create-rule`, { method: 'POST' })
    if (res.ok) {
      const rule = await res.json()
      alert(`Rule created: "${rule.name}" (id ${rule.id}). Adjust threshold/window in the Rules page if needed.`)
    }
  }

  const s = {
    card: { background: '#161b22', border: '1px solid #30363d', borderRadius: '10px', padding: '16px', marginBottom: '24px' },
    title: { color: '#e6edf3', fontWeight: 700, fontSize: '15px', marginBottom: '12px' },
    row: { display: 'flex', gap: '8px', marginBottom: '8px', alignItems: 'center' },
    select: { background: '#21262d', border: '1px solid #30363d', color: '#e6edf3', borderRadius: '6px', padding: '6px 10px', fontSize: '13px' },
    input: { background: '#21262d', border: '1px solid #30363d', color: '#e6edf3', borderRadius: '6px', padding: '6px 10px', fontSize: '13px', flex: 1 },
    btn: { background: '#21262d', border: '1px solid #30363d', color: '#8b949e', borderRadius: '6px', padding: '6px 12px', fontSize: '12px', cursor: 'pointer' },
    primaryBtn: { background: '#1f6feb', border: '1px solid #58a6ff', color: '#fff', borderRadius: '6px', padding: '8px 16px', fontSize: '13px', cursor: 'pointer', fontWeight: 600 },
    table: { width: '100%', borderCollapse: 'collapse', fontSize: '12px' },
    th: { background: '#0d1117', color: '#8b949e', padding: '8px 12px', textAlign: 'left', borderBottom: '1px solid #30363d' },
    td: { padding: '8px 12px', borderBottom: '1px solid #21262d', color: '#c9d1d9' },
    layout: { display: 'grid', gridTemplateColumns: '260px 1fr', gap: '24px' },
    sidebarItem: { padding: '10px 12px', borderBottom: '1px solid #21262d', display: 'flex', flexDirection: 'column', gap: '6px' },
  }

  return (
    <div style={s.layout}>
      {/* Saved hunts sidebar */}
      <div style={s.card}>
        <div style={s.title}>💾 Saved Hunts</div>
        {savedHunts.length === 0 ? (
          <div style={{ color: '#484f58', fontSize: '13px' }}>No saved hunts yet.</div>
        ) : (
          savedHunts.map(h => (
            <div key={h.id} style={s.sidebarItem}>
              <span style={{ color: '#e6edf3', fontSize: '13px', fontWeight: 600, cursor: 'pointer' }}
                onClick={() => loadHunt(h)}>
                {h.name}
              </span>
              <div style={{ display: 'flex', gap: '6px' }}>
                <button style={s.btn} onClick={() => createRule(h.id)}>→ Create Rule</button>
                <button style={s.btn} onClick={() => deleteHunt(h.id)}>🗑 Delete</button>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Filter builder + preview */}
      <div>
        <div style={s.card}>
          <div style={s.title}>🔎 Threat Hunt — Filter Builder</div>

          {conditions.map((cond, i) => (
            <div key={i} style={s.row}>
              <select style={s.select} value={cond.field} onChange={e => updateCondition(i, 'field', e.target.value)}>
                {FIELDS.map(f => <option key={f} value={f}>{f}</option>)}
              </select>
              <select style={s.select} value={cond.operator} onChange={e => updateCondition(i, 'operator', e.target.value)}>
                {OPERATORS.map(op => <option key={op} value={op}>{op}</option>)}
              </select>
              <input style={s.input} placeholder="value" value={cond.value}
                onChange={e => updateCondition(i, 'value', e.target.value)} />
              {conditions.length > 1 && (
                <button style={s.btn} onClick={() => removeCondition(i)}>✕</button>
              )}
            </div>
          ))}

          <div style={{ display: 'flex', gap: '10px', alignItems: 'center', marginTop: '10px' }}>
            <button style={s.btn} onClick={addCondition}>+ Add Condition</button>
            <select style={s.select} value={combinator} onChange={e => setCombinator(e.target.value)}>
              <option value="AND">Combine with AND</option>
              <option value="OR">Combine with OR</option>
            </select>
            <button style={s.primaryBtn} onClick={runPreview}>▶ Preview</button>
          </div>

          <div style={{ display: 'flex', gap: '10px', marginTop: '14px', alignItems: 'center' }}>
            <input style={s.input} placeholder="Name this hunt to save it…"
              value={huntName} onChange={e => setHuntName(e.target.value)} />
            <button style={s.btn} onClick={saveHunt}>💾 Save Hunt</button>
          </div>
        </div>

        <div style={s.card}>
          <div style={s.title}>Results {total > 0 && `(${total.toLocaleString()})`}</div>
          {error && <div style={{ color: '#f85149', fontSize: '13px', marginBottom: '10px' }}>⚠ {error}</div>}
          {results.length === 0 ? (
            <div style={{ color: '#484f58', fontSize: '13px', textAlign: 'center', padding: '30px' }}>
              {loading ? '⏳ Running…' : 'Run a preview to see matching logs.'}
            </div>
          ) : (
            <table style={s.table}>
              <thead>
                <tr>
                  <th style={s.th}>Timestamp</th>
                  <th style={s.th}>Source</th>
                  <th style={s.th}>IP</th>
                  <th style={s.th}>Action</th>
                  <th style={s.th}>Status</th>
                  <th style={s.th}>Message</th>
                </tr>
              </thead>
              <tbody>
                {results.map(log => (
                  <tr key={log.id}>
                    <td style={s.td}>{new Date(log.timestamp).toLocaleString()}</td>
                    <td style={s.td}>{log.source_type}</td>
                    <td style={s.td}>{log.source_ip || '—'}</td>
                    <td style={s.td}>{log.action || '—'}</td>
                    <td style={s.td}>{log.status_code || '—'}</td>
                    <td style={{ ...s.td, maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {log.message || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  )
}
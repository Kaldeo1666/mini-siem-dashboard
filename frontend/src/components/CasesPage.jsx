import { useState, useEffect } from 'react'

const STATUS_COLORS = {
  OPEN:           { bg: '#3d1c1c', color: '#f85149' },
  INVESTIGATING:  { bg: '#3d2b00', color: '#e3b341' },
  CLOSED:         { bg: '#1a2f1a', color: '#3fb950' },
}

const NEXT_STATUS = {
  OPEN: 'INVESTIGATING',
  INVESTIGATING: 'CLOSED',
  CLOSED: null,
}

export default function CasesPage({ apiBase }) {
  const [cases, setCases] = useState([])
  const [selectedCase, setSelectedCase] = useState(null)
  const [newTitle, setNewTitle] = useState('')
  const [newDesc, setNewDesc] = useState('')
  const [noteText, setNoteText] = useState('')
  const [noteAuthor, setNoteAuthor] = useState('')
  const [alertIdToAdd, setAlertIdToAdd] = useState('')
  const [error, setError] = useState(null)

  const fetchCases = async () => {
    try {
      const res = await fetch(`${apiBase}/cases`)
      if (res.ok) setCases((await res.json()).cases)
    } catch (e) { console.error(e) }
  }

  useEffect(() => { fetchCases() }, [])

  const openCase = async (id) => {
    try {
      const res = await fetch(`${apiBase}/cases/${id}`)
      if (res.ok) setSelectedCase(await res.json())
    } catch (e) { console.error(e) }
  }

  const createCase = async () => {
    if (!newTitle.trim()) return
    const res = await fetch(`${apiBase}/cases`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title: newTitle, description: newDesc || null }),
    })
    if (res.ok) {
      setNewTitle('')
      setNewDesc('')
      fetchCases()
    }
  }

  const transitionStatus = async (newStatus) => {
    if (!selectedCase) return
    const res = await fetch(`${apiBase}/cases/${selectedCase.id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus }),
    })
    if (res.ok) {
      await openCase(selectedCase.id)
      fetchCases()
    }
  }

  const addNote = async () => {
    if (!selectedCase || !noteText.trim()) return
    const res = await fetch(`${apiBase}/cases/${selectedCase.id}/notes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ note: noteText, author: noteAuthor || null }),
    })
    if (res.ok) {
      setNoteText('')
      openCase(selectedCase.id)
    }
  }

  const addAlert = async () => {
    if (!selectedCase || !alertIdToAdd) return
    setError(null)
    const res = await fetch(`${apiBase}/cases/${selectedCase.id}/alerts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ alert_id: Number(alertIdToAdd) }),
    })
    if (res.ok) {
      setAlertIdToAdd('')
      openCase(selectedCase.id)
    } else {
      const data = await res.json().catch(() => ({}))
      setError(data.detail || 'Failed to add alert')
    }
  }

  const s = {
    layout: { display: 'grid', gridTemplateColumns: '340px 1fr', gap: '24px' },
    card: { background: '#161b22', border: '1px solid #30363d', borderRadius: '10px', padding: '16px', marginBottom: '24px' },
    title: { color: '#e6edf3', fontWeight: 700, fontSize: '15px', marginBottom: '12px' },
    input: { background: '#21262d', border: '1px solid #30363d', color: '#e6edf3', borderRadius: '6px', padding: '6px 10px', fontSize: '13px', width: '100%', marginBottom: '8px' },
    btn: { background: '#21262d', border: '1px solid #30363d', color: '#8b949e', borderRadius: '6px', padding: '6px 12px', fontSize: '12px', cursor: 'pointer' },
    primaryBtn: { background: '#1f6feb', border: '1px solid #58a6ff', color: '#fff', borderRadius: '6px', padding: '8px 16px', fontSize: '13px', cursor: 'pointer', fontWeight: 600, width: '100%' },
    caseItem: { padding: '10px 12px', borderBottom: '1px solid #21262d', cursor: 'pointer' },
    badge: (colors) => ({ background: colors.bg, color: colors.color, borderRadius: '4px', padding: '2px 8px', fontSize: '11px', fontWeight: 700 }),
    noteItem: { padding: '10px 0', borderBottom: '1px solid #21262d', fontSize: '13px' },
    alertItem: { padding: '8px 0', borderBottom: '1px solid #21262d', fontSize: '13px', color: '#c9d1d9' },
  }

  return (
    <div style={s.layout}>
      {/* Case list */}
      <div>
        <div style={s.card}>
          <div style={s.title}>➕ New Case</div>
          <input style={s.input} placeholder="Case title…" value={newTitle} onChange={e => setNewTitle(e.target.value)} />
          <input style={s.input} placeholder="Description (optional)…" value={newDesc} onChange={e => setNewDesc(e.target.value)} />
          <button style={s.primaryBtn} onClick={createCase}>Create Case</button>
        </div>

        <div style={s.card}>
          <div style={s.title}>📁 Cases ({cases.length})</div>
          {cases.length === 0 ? (
            <div style={{ color: '#484f58', fontSize: '13px' }}>No cases yet.</div>
          ) : (
            cases.map(c => {
              const colors = STATUS_COLORS[c.status] || STATUS_COLORS.OPEN
              return (
                <div key={c.id} style={s.caseItem} onClick={() => openCase(c.id)}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ color: '#e6edf3', fontWeight: 600, fontSize: '13px' }}>{c.title}</span>
                    <span style={s.badge(colors)}>{c.status}</span>
                  </div>
                  {c.assignee && <div style={{ color: '#8b949e', fontSize: '11px', marginTop: '4px' }}>👤 {c.assignee}</div>}
                </div>
              )
            })
          )}
        </div>
      </div>

      {/* Case detail */}
      <div style={s.card}>
        {!selectedCase ? (
          <div style={{ color: '#484f58', textAlign: 'center', padding: '60px', fontSize: '14px' }}>
            Select a case from the list to view details.
          </div>
        ) : (
          <>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
              <div>
                <div style={{ color: '#e6edf3', fontWeight: 700, fontSize: '18px' }}>{selectedCase.title}</div>
                {selectedCase.description && (
                  <div style={{ color: '#8b949e', fontSize: '13px', marginTop: '4px' }}>{selectedCase.description}</div>
                )}
              </div>
              <span style={s.badge(STATUS_COLORS[selectedCase.status] || STATUS_COLORS.OPEN)}>
                {selectedCase.status}
              </span>
            </div>

            {NEXT_STATUS[selectedCase.status] && (
              <button style={{ ...s.btn, marginBottom: '20px' }}
                onClick={() => transitionStatus(NEXT_STATUS[selectedCase.status])}>
                → Move to {NEXT_STATUS[selectedCase.status]}
              </button>
            )}

            {/* Linked alerts */}
            <div style={{ marginBottom: '20px' }}>
              <div style={s.title}>🚨 Linked Alerts ({selectedCase.alerts.length})</div>
              {error && <div style={{ color: '#f85149', fontSize: '12px', marginBottom: '8px' }}>⚠ {error}</div>}
              <div style={{ display: 'flex', gap: '8px', marginBottom: '10px' }}>
                <input style={{ ...s.input, marginBottom: 0 }} placeholder="Alert ID to link…"
                  value={alertIdToAdd} onChange={e => setAlertIdToAdd(e.target.value)} />
                <button style={s.btn} onClick={addAlert}>Add</button>
              </div>
              {selectedCase.alerts.length === 0 ? (
                <div style={{ color: '#484f58', fontSize: '13px' }}>No alerts linked yet.</div>
              ) : (
                selectedCase.alerts.map(a => (
                  <div key={a.id} style={s.alertItem}>
                    <strong>{a.rule_name}</strong> · {a.severity} · {a.source_ip || 'no IP'} · {new Date(a.triggered_at).toLocaleString()}
                  </div>
                ))
              )}
            </div>

            {/* Notes timeline */}
            <div>
              <div style={s.title}>📝 Investigation Notes ({selectedCase.notes.length})</div>
              <div style={{ display: 'flex', gap: '8px', marginBottom: '10px' }}>
                <input style={{ ...s.input, marginBottom: 0, flex: 2 }} placeholder="Author (optional)"
                  value={noteAuthor} onChange={e => setNoteAuthor(e.target.value)} />
                <input style={{ ...s.input, marginBottom: 0, flex: 3 }} placeholder="Add a note…"
                  value={noteText} onChange={e => setNoteText(e.target.value)} />
                <button style={s.btn} onClick={addNote}>Add</button>
              </div>
              {selectedCase.notes.length === 0 ? (
                <div style={{ color: '#484f58', fontSize: '13px' }}>No notes yet.</div>
              ) : (
                selectedCase.notes.map(n => (
                  <div key={n.id} style={s.noteItem}>
                    <div style={{ color: '#c9d1d9' }}>{n.note}</div>
                    <div style={{ color: '#6e7681', fontSize: '11px', marginTop: '2px' }}>
                      {n.author || 'Unknown'} · {new Date(n.created_at).toLocaleString()}
                    </div>
                  </div>
                ))
              )}
            </div>
          </>
        )}
      </div>
    </div>
  )
}
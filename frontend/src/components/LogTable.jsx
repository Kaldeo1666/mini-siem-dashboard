import { useState, useEffect, useCallback } from 'react'
import { API_HEADERS } from '../App.jsx'

// ── Constants ──────────────────────────────────────────────────────────────

const LEVEL_BADGE = {
  DEBUG:    { bg: '#21262d', color: '#8b949e', border: '#30363d' },
  INFO:     { bg: '#1f3a5f', color: '#58a6ff', border: '#1f6feb' },
  WARN:     { bg: '#3d2b00', color: '#e3b341', border: '#9e6a03' },
  ERROR:    { bg: '#3d1c1c', color: '#f85149', border: '#da3633' },
  CRITICAL: { bg: '#4a0e0e', color: '#ff7b72', border: '#f85149' },
}

const SOURCE_TYPES = ['apache', 'nginx', 'syslog', 'json', 'firewall', 'windows_event']
const LEVELS       = ['DEBUG', 'INFO', 'WARN', 'ERROR', 'CRITICAL']
const PAGE_SIZES   = [25, 50, 100]

const TIME_PRESETS = [
  { label: 'Last 1h',  hours: 1  },
  { label: 'Last 6h',  hours: 6  },
  { label: 'Last 24h', hours: 24 },
  { label: 'All',      hours: null },
]

// ── Helpers ────────────────────────────────────────────────────────────────

function fmtTs(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  return d.toLocaleString('en-GB', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: false,
  })
}

function LevelBadge({ level }) {
  const c = LEVEL_BADGE[level] || LEVEL_BADGE.INFO
  return (
    <span style={{
      background: c.bg, color: c.color,
      border: `1px solid ${c.border}`,
      borderRadius: '4px', padding: '1px 7px',
      fontSize: '11px', fontWeight: 600, whiteSpace: 'nowrap',
    }}>
      {level}
    </span>
  )
}

function SortIcon({ col, sortBy, sortDir }) {
  if (sortBy !== col) return <span style={{ color: '#30363d', marginLeft: 4 }}>⇅</span>
  return <span style={{ color: '#58a6ff', marginLeft: 4 }}>{sortDir === 'asc' ? '↑' : '↓'}</span>
}

// ── Styles ─────────────────────────────────────────────────────────────────

const s = {
  card: {
    background: '#161b22', border: '1px solid #30363d',
    borderRadius: '10px', overflow: 'hidden',
  },
  toolbar: {
    padding: '14px 16px', borderBottom: '1px solid #30363d',
    display: 'flex', flexWrap: 'wrap', gap: '10px', alignItems: 'center',
  },
  select: {
    background: '#21262d', border: '1px solid #30363d', color: '#e6edf3',
    borderRadius: '6px', padding: '6px 10px', fontSize: '13px', cursor: 'pointer',
  },
  input: {
    background: '#21262d', border: '1px solid #30363d', color: '#e6edf3',
    borderRadius: '6px', padding: '6px 10px', fontSize: '13px', outline: 'none',
    width: '200px',
  },
  presetBtn: (active) => ({
    background: active ? '#1f6feb' : '#21262d',
    border: `1px solid ${active ? '#58a6ff' : '#30363d'}`,
    color: active ? '#ffffff' : '#8b949e',
    borderRadius: '6px', padding: '6px 12px', fontSize: '12px',
    cursor: 'pointer', fontWeight: active ? 600 : 400,
  }),
  table: {
    width: '100%', borderCollapse: 'collapse', fontSize: '12.5px',
  },
  th: {
    background: '#0d1117', color: '#8b949e', fontWeight: 600,
    padding: '10px 12px', textAlign: 'left', borderBottom: '1px solid #30363d',
    cursor: 'pointer', userSelect: 'none', whiteSpace: 'nowrap',
  },
  td: {
    padding: '9px 12px', borderBottom: '1px solid #21262d',
    verticalAlign: 'top', color: '#c9d1d9',
  },
  trHover: {
    background: '#1c2128',
  },
  pagination: {
    padding: '12px 16px', display: 'flex', alignItems: 'center',
    gap: '8px', borderTop: '1px solid #30363d', flexWrap: 'wrap',
  },
  pageBtn: (active, disabled) => ({
    background: active ? '#1f6feb' : '#21262d',
    border: `1px solid ${active ? '#58a6ff' : '#30363d'}`,
    color: disabled ? '#484f58' : (active ? '#fff' : '#c9d1d9'),
    borderRadius: '6px', padding: '5px 11px', fontSize: '12px',
    cursor: disabled ? 'not-allowed' : 'pointer',
    fontWeight: active ? 600 : 400,
  }),
  emptyRow: {
    textAlign: 'center', padding: '40px', color: '#484f58', fontSize: '14px',
  },
  refreshBtn: {
    background: '#21262d', border: '1px solid #30363d', color: '#8b949e',
    borderRadius: '6px', padding: '6px 12px', fontSize: '12px',
    cursor: 'pointer', marginLeft: 'auto',
  },
}

// ── Columns ────────────────────────────────────────────────────────────────

const COLUMNS = [
  { key: 'timestamp',   label: 'Timestamp',    sortable: true,  width: '160px' },
  { key: 'level',       label: 'Level',        sortable: false, width: '80px'  },
  { key: 'source_type', label: 'Source',       sortable: true,  width: '90px'  },
  { key: 'source_host', label: 'Host',         sortable: true,  width: '120px' },
  { key: 'source_ip',   label: 'Source IP',    sortable: true,  width: '120px' },
  { key: 'action',      label: 'Action',       sortable: false, width: '180px' },
  { key: 'status_code', label: 'Status',       sortable: true,  width: '70px'  },
  { key: 'message',     label: 'Message',      sortable: false, width: 'auto'  },
]

// ── Main component ─────────────────────────────────────────────────────────

export default function LogTable({ apiBase }) {
  const [logs, setLogs]           = useState([])
  const [total, setTotal]         = useState(0)
  const [totalPages, setTotalPages] = useState(1)
  const [loading, setLoading]     = useState(false)
  const [error, setError]         = useState(null)
  const [hoveredRow, setHoveredRow] = useState(null)

  // Pagination
  const [page, setPage]           = useState(1)
  const [pageSize, setPageSize]   = useState(50)

  // Sorting
  const [sortBy, setSortBy]       = useState('timestamp')
  const [sortDir, setSortDir]     = useState('desc')

  // Filters
  const [sourceType, setSourceType] = useState('')
  const [level, setLevel]           = useState('')
  const [search, setSearch]         = useState('')
  const [searchInput, setSearchInput] = useState('') // debounced
  const [timePreset, setTimePreset]   = useState(3)  // index into TIME_PRESETS; 3 = All

  // Compute time_from from preset
  const getTimeFrom = () => {
    const preset = TIME_PRESETS[timePreset]
    if (!preset.hours) return null
    const d = new Date()
    d.setHours(d.getHours() - preset.hours)
    return d.toISOString()
  }

  // Fetch logs
  const fetchLogs = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const params = new URLSearchParams({
        page: String(page),
        page_size: String(pageSize),
        sort_by: sortBy,
        sort_dir: sortDir,
      })
      if (sourceType) params.set('source_type', sourceType)
      if (level)      params.set('level', level)
      if (search)     params.set('search', search)
      const tf = getTimeFrom()
      if (tf) params.set('time_from', tf)

      const res = await fetch(`${apiBase}/logs?${params}`, { headers: API_HEADERS })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      setLogs(data.logs)
      setTotal(data.total)
      setTotalPages(data.total_pages)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [apiBase, page, pageSize, sortBy, sortDir, sourceType, level, search, timePreset])

  // Debounce search input
  useEffect(() => {
    const t = setTimeout(() => setSearch(searchInput), 400)
    return () => clearTimeout(t)
  }, [searchInput])

  // Reset to page 1 when filters change
  useEffect(() => { setPage(1) }, [sourceType, level, search, timePreset, pageSize])

  // Fetch when dependencies change
  useEffect(() => { fetchLogs() }, [fetchLogs])

  // Auto-refresh every 10s
  useEffect(() => {
    const interval = setInterval(fetchLogs, 10_000)
    return () => clearInterval(interval)
  }, [fetchLogs])

  // Column sort handler
  const handleSort = (col) => {
    if (!COLUMNS.find(c => c.key === col)?.sortable) return
    if (sortBy === col) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    } else {
      setSortBy(col)
      setSortDir('desc')
    }
    setPage(1)
  }

  // Pagination helpers
  const pageNumbers = () => {
    const pages = []
    const start = Math.max(1, page - 2)
    const end   = Math.min(totalPages, page + 2)
    for (let i = start; i <= end; i++) pages.push(i)
    return pages
  }

  return (
    <div style={s.card}>
      {/* ── Toolbar ── */}
      <div style={s.toolbar}>
        {/* Time range presets */}
        <div style={{ display: 'flex', gap: '6px' }}>
          {TIME_PRESETS.map((p, i) => (
            <button key={p.label} style={s.presetBtn(timePreset === i)}
              onClick={() => setTimePreset(i)}>
              {p.label}
            </button>
          ))}
        </div>

        {/* Source type filter */}
        <select style={s.select} value={sourceType}
          onChange={e => setSourceType(e.target.value)}>
          <option value="">All Sources</option>
          {SOURCE_TYPES.map(t => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>

        {/* Level filter */}
        <select style={s.select} value={level}
          onChange={e => setLevel(e.target.value)}>
          <option value="">All Levels</option>
          {LEVELS.map(l => (
            <option key={l} value={l}>{l}</option>
          ))}
        </select>

        {/* Message search */}
        <input
          style={s.input}
          placeholder="🔍  Search message…"
          value={searchInput}
          onChange={e => setSearchInput(e.target.value)}
        />

        {/* Rows per page */}
        <select style={s.select} value={pageSize}
          onChange={e => setPageSize(Number(e.target.value))}>
          {PAGE_SIZES.map(n => (
            <option key={n} value={n}>{n} / page</option>
          ))}
        </select>

        {/* Result count + refresh */}
        <span style={{ color: '#8b949e', fontSize: '12px' }}>
          {loading ? 'Loading…' : `${total.toLocaleString()} results`}
        </span>
        <button style={s.refreshBtn} onClick={fetchLogs} title="Refresh now">
          ↻ Refresh
        </button>
      </div>

      {/* ── Error banner ── */}
      {error && (
        <div style={{
          background: '#3d1c1c', color: '#f85149', padding: '10px 16px',
          borderBottom: '1px solid #da3633', fontSize: '13px',
        }}>
          ⚠ Could not fetch logs: {error}. Is the API running?
        </div>
      )}

      {/* ── Table ── */}
      <div style={{ overflowX: 'auto' }}>
        <table style={s.table}>
          <thead>
            <tr>
              {COLUMNS.map(col => (
                <th key={col.key} style={{ ...s.th, width: col.width }}
                  onClick={() => handleSort(col.key)}>
                  {col.label}
                  {col.sortable && (
                    <SortIcon col={col.key} sortBy={sortBy} sortDir={sortDir} />
                  )}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {logs.length === 0 ? (
              <tr>
                <td colSpan={COLUMNS.length} style={s.emptyRow}>
                  {loading
                    ? '⏳ Loading logs…'
                    : '📭 No logs found. Run the generator script or ingest some logs.'}
                </td>
              </tr>
            ) : (
              logs.map(log => (
                <tr key={log.id}
                  onMouseEnter={() => setHoveredRow(log.id)}
                  onMouseLeave={() => setHoveredRow(null)}
                  style={hoveredRow === log.id ? s.trHover : {}}>

                  <td style={{ ...s.td, fontFamily: 'monospace', fontSize: '12px', whiteSpace: 'nowrap' }}>
                    {fmtTs(log.timestamp)}
                  </td>
                  <td style={s.td}>
                    <LevelBadge level={log.level} />
                  </td>
                  <td style={{ ...s.td, color: '#8b949e', fontFamily: 'monospace' }}>
                    {log.source_type}
                  </td>
                  <td style={{ ...s.td, fontFamily: 'monospace', fontSize: '12px' }}>
                    {log.source_host || '—'}
                  </td>
                  <td style={{ ...s.td, fontFamily: 'monospace', fontSize: '12px', color: '#79c0ff' }}>
                    {log.source_ip || '—'}
                  </td>
                  <td style={{ ...s.td, fontFamily: 'monospace', fontSize: '12px', maxWidth: '200px',
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {log.action || '—'}
                  </td>
                  <td style={{ ...s.td, textAlign: 'center' }}>
                    {log.status_code ? (
                      <span style={{
                        color: log.status_code >= 500 ? '#f85149'
                             : log.status_code >= 400 ? '#e3b341'
                             : '#3fb950',
                        fontWeight: 600, fontFamily: 'monospace',
                      }}>
                        {log.status_code}
                      </span>
                    ) : '—'}
                  </td>
                  <td style={{ ...s.td, maxWidth: '400px',
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                    color: '#8b949e', fontSize: '12px' }}>
                    {log.ioc_matched && (
                      <span style={{ color: '#f85149', marginRight: '6px' }}
                        title="IOC Match">🚨</span>
                    )}
                    {log.message || '—'}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* ── Pagination ── */}
      <div style={s.pagination}>
        <button style={s.pageBtn(false, page === 1)}
          disabled={page === 1} onClick={() => setPage(1)}>«</button>
        <button style={s.pageBtn(false, page === 1)}
          disabled={page === 1} onClick={() => setPage(p => p - 1)}>‹</button>

        {pageNumbers().map(n => (
          <button key={n} style={s.pageBtn(n === page, false)}
            onClick={() => setPage(n)}>{n}</button>
        ))}

        <button style={s.pageBtn(false, page === totalPages)}
          disabled={page === totalPages} onClick={() => setPage(p => p + 1)}>›</button>
        <button style={s.pageBtn(false, page === totalPages)}
          disabled={page === totalPages} onClick={() => setPage(totalPages)}>»</button>

        <span style={{ color: '#8b949e', fontSize: '12px', marginLeft: '8px' }}>
          Page {page} of {totalPages}
        </span>
      </div>
    </div>
  )
}

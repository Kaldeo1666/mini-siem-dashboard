import { useState, useEffect, useCallback, useRef } from 'react'
import { FixedSizeList } from 'react-window'
import { API_HEADERS } from '../App.jsx'
import { COLORS } from '../theme.js'

// ── Constants ──────────────────────────────────────────────────────────────

const LEVEL_BADGE = {
  DEBUG:    { bg: COLORS.bgInset, color: COLORS.textSecondary, border: COLORS.border, icon: '⚪' },
  INFO:     { bg: '#0d1f3a', color: COLORS.severity.LOW.color, border: COLORS.severity.LOW.color, icon: '🔵' },
  WARN:     { bg: COLORS.severity.MEDIUM.bg, color: COLORS.severity.MEDIUM.color, border: COLORS.severity.MEDIUM.color, icon: '🟡' },
  ERROR:    { bg: COLORS.severity.HIGH.bg, color: COLORS.severity.HIGH.color, border: COLORS.severity.HIGH.color, icon: '🟠' },
  CRITICAL: { bg: COLORS.severity.CRITICAL.bg, color: COLORS.severity.CRITICAL.color, border: COLORS.severity.CRITICAL.color, icon: '🔴' },
}

const SOURCE_TYPES = ['apache', 'nginx', 'syslog', 'json', 'firewall', 'windows_event']
const LEVELS       = ['DEBUG', 'INFO', 'WARN', 'ERROR', 'CRITICAL']

// Virtualized fetch window: how many rows we pull in one request and
// keep in memory for the virtual list to scroll through. 2000 rows at
// ~1KB each is a small, fast payload, and react-window only ever
// renders the ~15-20 rows actually visible in the viewport regardless
// of how large this working set is -- this is what makes 10,000+ row
// datasets scroll smoothly instead of choking the DOM.
const FETCH_LIMIT = 10000
const ROW_HEIGHT = 36

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
      {c.icon} {level}
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
  headerRow: {
    display: 'flex', background: '#0d1117', borderBottom: '1px solid #30363d',
  },
  th: {
    color: '#8b949e', fontWeight: 600, fontSize: '12.5px',
    padding: '10px 12px', textAlign: 'left',
    cursor: 'pointer', userSelect: 'none', whiteSpace: 'nowrap',
    overflow: 'hidden', textOverflow: 'ellipsis',
  },
  row: {
    display: 'flex', alignItems: 'center', borderBottom: '1px solid #21262d',
  },
  td: {
    padding: '0 12px', color: '#c9d1d9', fontSize: '12.5px',
    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
  },
  emptyRow: {
    textAlign: 'center', padding: '40px', color: '#484f58', fontSize: '14px',
  },
  refreshBtn: {
    background: '#21262d', border: '1px solid #30363d', color: '#8b949e',
    borderRadius: '6px', padding: '6px 12px', fontSize: '12px',
    cursor: 'pointer', marginLeft: 'auto',
  },
}

// ── Columns (with fixed flex-basis widths for virtual row alignment) ───────

const COLUMNS = [
  { key: 'timestamp',   label: 'Timestamp',    sortable: true,  width: '160px' },
  { key: 'level',       label: 'Level',        sortable: false, width: '100px' },
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
  const [loading, setLoading]     = useState(false)
  const [error, setError]         = useState(null)
  const [hoveredRow, setHoveredRow] = useState(null)

  // Sorting
  const [sortBy, setSortBy]       = useState('timestamp')
  const [sortDir, setSortDir]     = useState('desc')

  // Filters
  const [sourceType, setSourceType] = useState('')
  const [level, setLevel]           = useState('')
  const [search, setSearch]         = useState('')
  const [searchInput, setSearchInput] = useState('') // debounced
  const [timePreset, setTimePreset]   = useState(3)  // index into TIME_PRESETS; 3 = All

  const listRef = useRef(null)

  // Compute time_from from preset
  const getTimeFrom = () => {
    const preset = TIME_PRESETS[timePreset]
    if (!preset.hours) return null
    const d = new Date()
    d.setHours(d.getHours() - preset.hours)
    return d.toISOString()
  }

  // Fetch logs -- pulls FETCH_LIMIT rows in one go for the virtual list
  // to scroll through, instead of paginating page-by-page.
  const fetchLogs = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const params = new URLSearchParams({
        page: '1',
        page_size: String(FETCH_LIMIT),
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
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [apiBase, sortBy, sortDir, sourceType, level, search, timePreset])

  // Debounce search input
  useEffect(() => {
    const t = setTimeout(() => setSearch(searchInput), 400)
    return () => clearTimeout(t)
  }, [searchInput])

  // Reset scroll to top when filters/sort change
  useEffect(() => {
    if (listRef.current) listRef.current.scrollTo(0)
  }, [sourceType, level, search, timePreset, sortBy, sortDir])

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
  }

  // ── Virtual row renderer ──
  const Row = ({ index, style }) => {
    const log = logs[index]
    if (!log) return null
    return (
      <div
        style={{ ...style, ...s.row, background: hoveredRow === log.id ? '#1c2128' : 'transparent' }}
        onMouseEnter={() => setHoveredRow(log.id)}
        onMouseLeave={() => setHoveredRow(null)}
      >
        <div style={{ ...s.td, flex: `0 0 160px`, fontFamily: 'monospace' }}>{fmtTs(log.timestamp)}</div>
        <div style={{ ...s.td, flex: `0 0 100px` }}><LevelBadge level={log.level} /></div>
        <div style={{ ...s.td, flex: `0 0 90px`, color: '#8b949e', fontFamily: 'monospace' }}>{log.source_type}</div>
        <div style={{ ...s.td, flex: `0 0 120px`, fontFamily: 'monospace' }}>{log.source_host || '—'}</div>
        <div style={{ ...s.td, flex: `0 0 120px`, fontFamily: 'monospace', color: '#79c0ff' }}>{log.source_ip || '—'}</div>
        <div style={{ ...s.td, flex: `0 0 180px`, fontFamily: 'monospace' }}>{log.action || '—'}</div>
        <div style={{ ...s.td, flex: `0 0 70px`, textAlign: 'center' }}>
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
        </div>
        <div style={{ ...s.td, flex: '1 1 auto', color: '#8b949e' }}>
          {log.ioc_matched && (
            <span style={{ color: '#f85149', marginRight: '6px' }} title="IOC Match">🚨</span>
          )}
          {log.message || '—'}
        </div>
      </div>
    )
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

        {/* Result count + refresh */}
        <span style={{ color: '#8b949e', fontSize: '12px' }}>
          {loading ? 'Loading…' : `${total.toLocaleString()} total · showing up to ${FETCH_LIMIT.toLocaleString()} (virtual scroll)`}
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

      {/* ── Header row ── */}
      <div style={s.headerRow}>
        {COLUMNS.map(col => (
          <div
            key={col.key}
            style={{ ...s.th, flex: col.width === 'auto' ? '1 1 auto' : `0 0 ${col.width}` }}
            onClick={() => handleSort(col.key)}
          >
            {col.label}
            {col.sortable && <SortIcon col={col.key} sortBy={sortBy} sortDir={sortDir} />}
          </div>
        ))}
      </div>

      {/* ── Virtualized body ── */}
      {logs.length === 0 ? (
        <div style={s.emptyRow}>
          {loading
            ? '⏳ Loading logs…'
            : '📭 No logs found. Run the generator script or ingest some logs.'}
        </div>
      ) : (
        <FixedSizeList
          ref={listRef}
          height={560}
          itemCount={logs.length}
          itemSize={ROW_HEIGHT}
          width="100%"
        >
          {Row}
        </FixedSizeList>
      )}
    </div>
  )
}
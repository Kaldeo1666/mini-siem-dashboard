/**
 * theme.js — Central color palette for the SOC dashboard (V5 Day 1).
 * Spec: dark gray background, semantic severity colors, monospace for
 * log/technical data, sans-serif for UI chrome.
 */

export const COLORS = {
  bg: '#0f1117',
  bgPanel: '#161b22',
  bgInset: '#0d1117',
  border: '#30363d',
  textPrimary: '#e6edf3',
  textSecondary: '#8b949e',
  textMuted: '#484f58',
  accent: '#3b82f6',

  severity: {
    CRITICAL: { color: '#ef4444', bg: '#3b0d0d', icon: '🔴' },
    HIGH:     { color: '#f97316', bg: '#3a1d06', icon: '🟠' },
    MEDIUM:   { color: '#eab308', bg: '#332905', icon: '🟡' },
    LOW:      { color: '#3b82f6', bg: '#0d1f3a', icon: '🔵' },
  },
}

export const FONT_MONO = "'JetBrains Mono', 'Fira Code', ui-monospace, monospace"
export const FONT_SANS = "-apple-system, 'Segoe UI', Roboto, sans-serif"

/** Returns { color, bg, icon } for a severity string, defaulting to LOW. */
export function severityStyle(severity) {
  return COLORS.severity[severity] || COLORS.severity.LOW
}
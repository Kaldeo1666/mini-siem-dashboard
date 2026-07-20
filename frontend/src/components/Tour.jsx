import { useEffect, useRef } from 'react'
import Shepherd from 'shepherd.js'
import 'shepherd.js/dist/css/shepherd.css'
import { COLORS } from '../theme.js'

/**
 * Guided dashboard tour (V5 Day 4).
 *
 * Mapping note: the spec asks for a step highlighting "the alert
 * severity heatmap," but no heatmap component exists in this app --
 * StatsBar's log-level counters are the closest existing
 * severity-at-a-glance view, substituted here rather than referencing
 * a UI element that doesn't exist. "Active alert counters" maps to the
 * Alerts panel's header count + filter tabs, since that's what
 * actually shows live counts today.
 */

const STEPS = [
  {
    id: 'events-chart',
    attachTo: { element: '#tour-events-chart', on: 'bottom' },
    title: '📈 Events / Minute',
    text: 'Live traffic volume across all ingested log sources, updated every few seconds.',
  },
  {
    id: 'alert-counters',
    attachTo: { element: '#tour-alerts-panel', on: 'bottom' },
    title: '🚨 Active Alerts',
    text: 'Real-time alert count and status filters. New detections appear here instantly via WebSocket.',
  },
  {
    id: 'severity-breakdown',
    attachTo: { element: '#tour-stats-bar', on: 'bottom' },
    title: '🎯 Severity Breakdown',
    text: 'A live count of logs by severity level, giving you an at-a-glance read on overall system health.',
  },
  {
    id: 'threat-hunting',
    attachTo: { element: '#tour-nav-hunt', on: 'bottom' },
    title: '🔎 Threat Hunting',
    text: 'Build ad-hoc filters to search across all ingested logs, save hunts for reuse, or promote a hunt into a detection rule.',
  },
  {
    id: 'case-management',
    attachTo: { element: '#tour-nav-cases', on: 'bottom' },
    title: '📁 Case Management',
    text: 'Group related alerts into an investigation, add notes, and track status from open to closed.',
  },
  {
    id: 'run-demo',
    attachTo: { element: '#tour-run-demo', on: 'bottom' },
    title: '▶ Run Demo',
    text: 'Resets demo data and runs a live 4-stage attack simulation -- watch alerts appear on the dashboard in real time.',
  },
]

const SHEPHERD_THEME_CSS = `
.shepherd-element {
  background: ${COLORS.bgPanel} !important;
  border: 1px solid ${COLORS.border} !important;
  border-radius: 10px !important;
}
.shepherd-text {
  color: ${COLORS.textPrimary} !important;
  font-size: 14px !important;
}
.shepherd-header {
  background: transparent !important;
  padding-top: 12px !important;
}
.shepherd-title {
  color: ${COLORS.textPrimary} !important;
  font-weight: 700 !important;
}
.shepherd-cancel-icon span {
  color: ${COLORS.textSecondary} !important;
}
.shepherd-button {
  background: ${COLORS.accent} !important;
  color: #fff !important;
  border-radius: 6px !important;
  font-size: 13px !important;
}
.shepherd-button.shepherd-button-secondary {
  background: ${COLORS.bgInset} !important;
  color: ${COLORS.textSecondary} !important;
}
.shepherd-arrow:before {
  background: ${COLORS.bgPanel} !important;
  border: 1px solid ${COLORS.border} !important;
}
`

export default function Tour({ launchSignal }) {
  const tourRef = useRef(null)

  useEffect(() => {
    const styleTag = document.createElement('style')
    styleTag.textContent = SHEPHERD_THEME_CSS
    document.head.appendChild(styleTag)
    return () => document.head.removeChild(styleTag)
  }, [])

  useEffect(() => {
    if (!launchSignal) return

    const tour = new Shepherd.Tour({
      useModalOverlay: true,
      defaultStepOptions: {
        classes: 'shepherd-theme-mini-siem',
        scrollTo: { behavior: 'smooth', block: 'center' },
        cancelIcon: { enabled: true },
      },
    })

    STEPS.forEach((step, i) => {
      const isFirst = i === 0
      const isLast = i === STEPS.length - 1
      tour.addStep({
        id: step.id,
        title: step.title,
        text: step.text,
        attachTo: step.attachTo,
        buttons: [
          ...(isFirst ? [] : [{ text: '← Back', action: tour.back, classes: 'shepherd-button-secondary' }]),
          { text: isLast ? 'Done' : 'Next →', action: isLast ? tour.complete : tour.next },
        ],
      })
    })

    tourRef.current = tour
    tour.start()

    return () => {
      if (tourRef.current) tourRef.current.complete()
    }
  }, [launchSignal])

  return null
}
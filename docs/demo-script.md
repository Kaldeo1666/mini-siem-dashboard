# Mini SIEM Dashboard — 5-Minute Demo Script

## Setup (before you start)
- `docker compose up -d` — confirm all 3 containers healthy
- Open http://localhost:3000 in a full-width browser window
- Have this script visible on a second screen or printed

---

## 1. Dashboard Overview (30s)

**Say:** "This is a self-hosted SIEM — Security Information and Event Management system — built from scratch. It ingests logs, detects threats using both static rules and statistical anomaly detection, and gives an analyst a live dashboard to investigate."

**Do:** Gesture at the dark SOC-themed dashboard. Point out the severity-coded alert counters and the live events/minute chart.

---

## 2. Raw Log Viewer (30s)

**Say:** "Every log — whether it's JSON, Apache access logs, or syslog — gets normalized into one common schema. This table is virtualized, so it stays smooth scrolling through hundreds of thousands of rows."

**Do:** Scroll the log table quickly to show smoothness. Point out the Level column's color-and-icon severity indicators.

---

## 3. Run Demo — Live Attack Simulation (2.5 min)

**Say:** "Let's simulate a real attack. This resets the demo data, then runs a live 4-stage attack against the system."

**Do:** Click **"▶ Run Demo"**.

- **Stage 1 (Recon, ~0-8s):** "First, a port scan — 50 rapid 404 requests. Watch the progress banner."
- **Stage 2 (Brute Force, ~8-16s):** "Now failed login attempts — this should trigger our Brute Force Login rule."
- **Stage 3 (Exploitation, ~16-24s):** "A successful admin login from the same attacker IP — a red flag for a compromised account."
- **Stage 4 (Exfiltration, ~24-32s):** "And finally, a large data transfer — simulating exfiltration."

**Do:** As each stage completes, point at the Alerts panel — new alerts should appear live via WebSocket, no page refresh needed. Call out the MITRE ATT&CK technique badges on each alert.

---

## 4. Case Management (1 min)

**Say:** "Let's investigate. I'll open a case and link the alerts we just saw."

**Do:**
1. Go to the **Cases** tab, create a new case ("Simulated Intrusion — Demo").
2. Link the **Brute Force Login** and **Suspicious Admin Access** alerts.
3. Add an investigation note: *"Confirmed brute force pattern followed by successful admin login from 10.99.0.1 — escalating."*
4. Transition the case status from OPEN → INVESTIGATING.

---

## 5. Incident Report (30s)

**Say:** "Finally, let's generate an incident report for this window."

**Do:**
1. Call the reports API directly (no dedicated UI button yet):
POST /reports/generate
{"start_iso": "<1 hour ago>", "end_iso": "<now>", "title": "Demo Incident Report"}

2. Open the returned report, scroll to the **MITRE ATT&CK heatmap** — point out the color-coded technique cells.

**Close:** "That's the full loop — ingest, detect, correlate, investigate, and report — all in one self-hosted stack."
import os
import json
from typing import List, Dict


class DashboardGenerator:
    def __init__(self, history_entries: List[Dict], base_report_dir: str):
        self.history_entries = history_entries
        self.base_report_dir = base_report_dir

    def generate(self) -> str:
        output_path = os.path.join(self.base_report_dir, "dashboard.html")

        data_json = json.dumps(self.history_entries)

        # We avoid f-strings so we don't have to escape all the { } in CSS/JS.
        html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Probe Scan Dashboard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <!-- Chart.js CDN -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --bg-main: #05070b;
            --bg-card: #0b1018;
            --bg-table: #0f1724;
            --border-subtle: #1f2933;
            --accent: #14b8a6;
            --accent-soft: rgba(20, 184, 166, 0.15);
            --text-main: #e5e7eb;
            --text-muted: #9ca3af;
            --risk-none: #9ca3af;
            --risk-low: #22c55e;
            --risk-medium: #eab308;
            --risk-high: #f97316;
            --risk-critical: #ef4444;
        }

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            padding: 24px;
            font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background: radial-gradient(circle at top, #020617, #02040a 50%, #000000 100%);
            color: var(--text-main);
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        h1 {
            margin: 0 0 8px;
            font-size: 28px;
            letter-spacing: 0.05em;
            color: var(--accent);
        }

        .subtitle {
            margin: 0 0 24px;
            color: var(--text-muted);
            font-size: 14px;
        }

        .header-row {
            display: flex;
            flex-wrap: wrap;
            gap: 16px;
            margin-bottom: 24px;
            align-items: center;
            justify-content: space-between;
        }

        .filters {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
        }

        .filter-group {
            display: flex;
            flex-direction: column;
            gap: 4px;
            font-size: 12px;
            color: var(--text-muted);
        }

        select {
            background: var(--bg-card);
            border: 1px solid var(--border-subtle);
            color: var(--text-main);
            padding: 6px 8px;
            border-radius: 6px;
            font-size: 13px;
            min-width: 160px;
        }

        .cards-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }

        .stat-card {
            background: linear-gradient(135deg, var(--bg-card), #020617);
            border-radius: 12px;
            padding: 12px 14px;
            border: 1px solid var(--border-subtle);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
        }

        .stat-label {
            font-size: 11px;
            text-transform: uppercase;
            color: var(--text-muted);
            letter-spacing: 0.08em;
        }

        .stat-value {
            margin-top: 6px;
            font-size: 20px;
            font-weight: 600;
        }

        .stat-sub {
            margin-top: 4px;
            font-size: 12px;
            color: var(--text-muted);
        }

        .chart-grid {
            display: grid;
            grid-template-columns: minmax(0, 2fr) minmax(0, 1.5fr);
            gap: 16px;
            margin-bottom: 24px;
        }

        .chart-card {
            background: var(--bg-card);
            border-radius: 12px;
            padding: 12px;
            border: 1px solid var(--border-subtle);
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.4);
        }

        .chart-title {
            font-size: 13px;
            margin-bottom: 8px;
            color: var(--text-muted);
        }

        canvas {
            width: 100% !important;
            height: 260px !important;
        }

        .table-card {
            background: var(--bg-table);
            border-radius: 12px;
            border: 1px solid var(--border-subtle);
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.5);
            overflow: hidden;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }

        thead {
            background: #020617;
        }

        th, td {
            padding: 8px 10px;
            border-bottom: 1px solid #111827;
        }

        th {
            text-align: left;
            font-weight: 500;
            color: var(--text-muted);
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }

        tbody tr:nth-child(even) {
            background: rgba(15, 23, 42, 0.9);
        }

        tbody tr:hover {
            background: rgba(15, 118, 110, 0.25);
        }

        .risk-badge {
            display: inline-flex;
            align-items: center;
            padding: 2px 8px;
            border-radius: 999px;
            font-size: 11px;
            font-weight: 600;
        }

        .risk-badge.none {
            color: var(--risk-none);
            background: rgba(148, 163, 184, 0.12);
        }

        .risk-badge.low {
            color: var(--risk-low);
            background: rgba(34, 197, 94, 0.12);
        }

        .risk-badge.medium {
            color: var(--risk-medium);
            background: rgba(234, 179, 8, 0.12);
        }

        .risk-badge.high {
            color: var(--risk-high);
            background: rgba(249, 115, 22, 0.12);
        }

        .risk-badge.critical {
            color: var(--risk-critical);
            background: rgba(239, 68, 68, 0.12);
        }

        .tag {
            font-size: 11px;
            color: var(--text-muted);
        }

        .nowrap {
            white-space: nowrap;
        }

        @media (max-width: 900px) {
            .chart-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Probe SOC Dashboard</h1>
        <p class="subtitle">Historical overview of security assessments performed by Probe.</p>

        <div class="header-row">
            <div class="filters">
                <div class="filter-group">
                    <label for="clientFilter">Client</label>
                    <select id="clientFilter">
                        <option value="__all__">All Clients</option>
                    </select>
                </div>
                <div class="filter-group">
                    <label for="targetFilter">Target</label>
                    <select id="targetFilter">
                        <option value="__all__">All Targets</option>
                    </select>
                </div>
            </div>
            <div class="tag">
                Data source: <code>scan_history.json</code>
            </div>
        </div>

        <div class="cards-row">
            <div class="stat-card">
                <div class="stat-label">Total Scans</div>
                <div class="stat-value" id="statTotalScans">0</div>
                <div class="stat-sub" id="statTotalClients"></div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Average Risk Score</div>
                <div class="stat-value" id="statAvgRisk">0</div>
                <div class="stat-sub" id="statCurrentRiskLevel"></div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Total Findings</div>
                <div class="stat-value" id="statTotalFindings">0</div>
                <div class="stat-sub" id="statSeverityBreakdown"></div>
            </div>
        </div>

        <div class="chart-grid">
            <div class="chart-card">
                <div class="chart-title">Risk Score Over Time</div>
                <canvas id="riskTrendChart"></canvas>
            </div>
            <div class="chart-card">
                <div class="chart-title">Findings by Severity (All Shown Scans)</div>
                <canvas id="severityChart"></canvas>
            </div>
        </div>

        <div class="table-card">
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Client</th>
                        <th>Target</th>
                        <th>Risk</th>
                        <th>Score</th>
                        <th>Findings</th>
                        <th>Report Directory</th>
                    </tr>
                </thead>
                <tbody id="scanTableBody"></tbody>
            </table>
        </div>
    </div>

    <script>
        const SCAN_DATA = __SCAN_DATA__;

        function normalizeLevel(level) {
            if (!level) return "NONE";
            return String(level).toUpperCase();
        }

        function riskClass(level) {
            const lv = normalizeLevel(level);
            if (lv === "CRITICAL") return "critical";
            if (lv === "HIGH") return "high";
            if (lv === "MEDIUM") return "medium";
            if (lv === "LOW") return "low";
            if (lv === "NONE") return "none";
            return "none";
        }

        let currentClientFilter = "__all__";
        let currentTargetFilter = "__all__";

        let riskTrendChart = null;
        let severityChart = null;

        function getFilteredData() {
            return SCAN_DATA.filter(entry => {
                const client = entry.client_name || "";
                const target = entry.target || "";
                if (currentClientFilter !== "__all__" && client !== currentClientFilter) {
                    return false;
                }
                if (currentTargetFilter !== "__all__" && target !== currentTargetFilter) {
                    return false;
                }
                return true;
            });
        }

        function populateFilters() {
            const clientSelect = document.getElementById("clientFilter");
            const targetSelect = document.getElementById("targetFilter");

            const clients = new Set();
            const targets = new Set();

            SCAN_DATA.forEach(entry => {
                if (entry.client_name) clients.add(entry.client_name);
                if (entry.target) targets.add(entry.target);
            });

            Array.from(clients).sort().forEach(c => {
                const opt = document.createElement("option");
                opt.value = c;
                opt.textContent = c;
                clientSelect.appendChild(opt);
            });

            Array.from(targets).sort().forEach(t => {
                const opt = document.createElement("option");
                opt.value = t;
                opt.textContent = t;
                targetSelect.appendChild(opt);
            });

            clientSelect.addEventListener("change", () => {
                currentClientFilter = clientSelect.value;
                redrawEverything();
            });

            targetSelect.addEventListener("change", () => {
                currentTargetFilter = targetSelect.value;
                redrawEverything();
            });
        }

        function populateTable(filtered) {
            const tbody = document.getElementById("scanTableBody");
            tbody.innerHTML = "";

            const sorted = filtered.slice().sort((a, b) => {
                const ta = a.timestamp || "";
                const tb = b.timestamp || "";
                return ta < tb ? 1 : (ta > tb ? -1 : 0);
            });

            sorted.forEach(entry => {
                const tr = document.createElement("tr");

                const risk = entry.risk || {};
                const level = normalizeLevel(risk.level || "NONE");
                const score = risk.normalized_score != null ? risk.normalized_score : 0;
                const totals = entry.totals || {};
                const findingsCount = totals.findings || 0;

                const tdTime = document.createElement("td");
                tdTime.textContent = entry.timestamp || "";
                tr.appendChild(tdTime);

                const tdClient = document.createElement("td");
                tdClient.textContent = entry.client_name || "";
                tr.appendChild(tdClient);

                const tdTarget = document.createElement("td");
                tdTarget.textContent = entry.target || "";
                tr.appendChild(tdTarget);

                const tdRisk = document.createElement("td");
                const badge = document.createElement("span");
                badge.className = "risk-badge " + riskClass(level);
                badge.textContent = level;
                tdRisk.appendChild(badge);
                tr.appendChild(tdRisk);

                const tdScore = document.createElement("td");
                tdScore.textContent = score;
                tr.appendChild(tdScore);

                const tdFindings = document.createElement("td");
                tdFindings.textContent = findingsCount;
                tr.appendChild(tdFindings);

                const tdDir = document.createElement("td");
                tdDir.textContent = entry.output_directory || "";
                tr.appendChild(tdDir);

                tbody.appendChild(tr);
            });
        }

        function updateStats(filtered) {
            const totalScans = filtered.length;
            const statTotalScans = document.getElementById("statTotalScans");
            const statTotalClients = document.getElementById("statTotalClients");
            const statAvgRisk = document.getElementById("statAvgRisk");
            const statCurrentRiskLevel = document.getElementById("statCurrentRiskLevel");
            const statTotalFindings = document.getElementById("statTotalFindings");
            const statSeverityBreakdown = document.getElementById("statSeverityBreakdown");

            statTotalScans.textContent = totalScans;

            const clientSet = new Set(filtered.map(e => e.client_name || "").filter(Boolean));
            statTotalClients.textContent = clientSet.size > 0
                ? `${clientSet.size} client(s) in view`
                : "No client data";

            let sumRisk = 0;
            let totalFindings = 0;
            const sevAgg = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };

            filtered.forEach(entry => {
                const risk = entry.risk || {};
                const score = risk.normalized_score != null ? risk.normalized_score : 0;
                sumRisk += score;

                const totals = entry.totals || {};
                totalFindings += totals.findings || 0;

                const bySev = totals.by_severity || {};
                Object.keys(bySev).forEach(k => {
                    const key = String(k).toUpperCase();
                    if (sevAgg[key] != null) {
                        sevAgg[key] += bySev[k] || 0;
                    }
                });
            });

            const avgRisk = totalScans > 0 ? (sumRisk / totalScans) : 0;
            statAvgRisk.textContent = avgRisk.toFixed(1);

            // Use the most recent scan for current risk label
            let currentLevel = "NONE";
            if (filtered.length > 0) {
                const sorted = filtered.slice().sort((a, b) => {
                    const ta = a.timestamp || "";
                    const tb = b.timestamp || "";
                    return ta < tb ? 1 : (ta > tb ? -1 : 0);
                });
                const latest = sorted[0];
                currentLevel = normalizeLevel((latest.risk || {}).level || "NONE");
            }
            statCurrentRiskLevel.textContent = `Most recent: ${currentLevel}`;

            statTotalFindings.textContent = totalFindings;

            const parts = [];
            Object.entries(sevAgg).forEach(([k, v]) => {
                if (v > 0) {
                    parts.push(`${k}: ${v}`);
                }
            });
            statSeverityBreakdown.textContent = parts.length > 0
                ? parts.join("  ·  ")
                : "No findings in view";
        }

        function renderRiskTrendChart(filtered) {
            const ctx = document.getElementById("riskTrendChart").getContext("2d");

            const sorted = filtered.slice().sort((a, b) => {
                const ta = a.timestamp || "";
                const tb = b.timestamp || "";
                return ta < tb ? -1 : (ta > tb ? 1 : 0);
            });

            const labels = sorted.map(e => e.timestamp || "");
            const data = sorted.map(e => {
                const risk = e.risk || {};
                return risk.normalized_score != null ? risk.normalized_score : 0;
            });

            if (riskTrendChart) {
                riskTrendChart.destroy();
            }

            riskTrendChart = new Chart(ctx, {
                type: "line",
                data: {
                    labels,
                    datasets: [
                        {
                            label: "Risk Score",
                            data,
                            borderColor: "#14b8a6",
                            backgroundColor: "rgba(20, 184, 166, 0.25)",
                            tension: 0.25,
                            pointRadius: 3,
                            pointHoverRadius: 5,
                        },
                    ],
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            labels: { color: "#e5e7eb", font: { size: 11 } },
                        },
                    },
                    scales: {
                        x: {
                            grid: { color: "rgba(31,41,55,0.6)" },
                            ticks: { color: "#9ca3af", maxRotation: 45, minRotation: 0 },
                        },
                        y: {
                            grid: { color: "rgba(31,41,55,0.6)" },
                            ticks: { color: "#9ca3af" },
                            suggestedMin: 0,
                            suggestedMax: 100,
                        },
                    },
                },
            });
        }

        function renderSeverityChart(filtered) {
            const ctx = document.getElementById("severityChart").getContext("2d");

            const agg = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };

            filtered.forEach(entry => {
                const bySev = (entry.totals || {}).by_severity || {};
                Object.keys(bySev).forEach(k => {
                    const key = String(k).toUpperCase();
                    if (agg[key] != null) {
                        agg[key] += bySev[k] || 0;
                    }
                });
            });

            const labels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
            const data = labels.map(l => agg[l]);

            if (severityChart) {
                severityChart.destroy();
            }

            severityChart = new Chart(ctx, {
                type: "doughnut",
                data: {
                    labels,
                    datasets: [
                        {
                            data,
                            backgroundColor: [
                                "#ef4444",
                                "#f97316",
                                "#eab308",
                                "#22c55e",
                                "#9ca3af",
                            ],
                            borderWidth: 0,
                        },
                    ],
                },
                options: {
                    plugins: {
                        legend: {
                            position: "bottom",
                            labels: { color: "#e5e7eb", font: { size: 11 } },
                        },
                    },
                },
            });
        }

        function redrawEverything() {
            const filtered = getFilteredData();
            populateTable(filtered);
            updateStats(filtered);
            renderRiskTrendChart(filtered);
            renderSeverityChart(filtered);
        }

        // Init
        document.addEventListener("DOMContentLoaded", () => {
            populateFilters();
            redrawEverything();
        });
    </script>
</body>
</html>
"""

        html = html.replace("__SCAN_DATA__", data_json)

        os.makedirs(self.base_report_dir, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        return output_path

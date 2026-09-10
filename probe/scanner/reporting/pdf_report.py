from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
from datetime import datetime
import os
from pathlib import Path


class PDFReportGenerator:
    def __init__(
        self,
        report_data: dict,
        output_directory: str,
        client_name: str,
        output_name: str = "report",
    ):
        self.report_data = report_data
        self.output_directory = output_directory
        self.client_name = client_name
        self.output_name = output_name
        self.styles = getSampleStyleSheet()
        self.timestamp = self._resolve_timestamp()

    def _resolve_timestamp(self) -> str:
        timestamp = self.report_data.get("timestamp") or self.report_data.get(
            "generated_at"
        )
        if timestamp:
            try:
                clean = timestamp.replace("Z", "")
                return datetime.fromisoformat(clean).strftime("%B %d, %Y")
            except ValueError:
                pass
        return datetime.now().strftime("%B %d, %Y")

    def generate(self):
        output_root = Path(self.output_directory).resolve()
        output_root.mkdir(parents=True, exist_ok=True)
        pdf_path = output_root / f"{self.output_name}.pdf"

        doc = SimpleDocTemplate(
            str(pdf_path),
            pagesize=LETTER,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72,
        )

        elements = []

        stats = self.report_data.get("statistics", {})
        severity_stats = stats.get("findings_by_severity", {})
        risk = stats.get("risk", {})
        raw_risk = risk.get("raw_score", 0)
        normalized_risk = risk.get("normalized_score", 0)
        vuln_total = stats.get('total_findings', 0)
        warning_total = stats.get('warning_findings', 0)
        info_total = stats.get('informational_findings', 0)
        edge_total = stats.get('edge_infrastructure_findings', 0)

        # COVER
        elements.append(Paragraph("Probe Security Assessment Report", self.styles["Title"]))
        elements.append(Spacer(1, 0.3 * inch))

        elements.append(Paragraph(f"<b>Client:</b> {self.client_name}", self.styles["Normal"]))
        elements.append(Paragraph(f"<b>Target:</b> {self.report_data.get('target')}", self.styles["Normal"]))
        elements.append(Paragraph(f"<b>Date:</b> {self.timestamp}", self.styles["Normal"]))
        elements.append(Paragraph(f"<b>Scan ID:</b> {self.report_data.get('scan_id')}", self.styles["Normal"]))

        elements.append(PageBreak())

        # EXEC SUMMARY
        elements.append(Paragraph("Executive Summary", self.styles["Heading1"]))
        elements.append(Spacer(1, 0.2 * inch))

        summary_text = (
            "This report presents the results of an automated security assessment performed using Probe. "
            "The objective of this assessment was to identify vulnerabilities, misconfigurations, and known "
            "security risks that could impact the target system."
        )
        elements.append(Paragraph(summary_text, self.styles["Normal"]))
        elements.append(Spacer(1, 0.2 * inch))

        elements.append(Paragraph("Overall Risk Posture", self.styles["Heading2"]))
        elements.append(Spacer(1, 0.1 * inch))

        elements.append(
            Paragraph(
                f"Overall Risk Level: <b>{risk.get('level', 'unknown').upper()}</b>",
                self.styles["Normal"],
            )
        )
        elements.append(
            Paragraph(
                f"Risk Score: {normalized_risk} / 100 (raw: {raw_risk})",
                self.styles["Normal"],
            )
        )
        elements.append(Spacer(1, 0.2 * inch))

        elements.append(Paragraph("Vulnerabilities by Severity", self.styles["Heading2"]))
        for sev, count in severity_stats.items():
            if count > 0:
                elements.append(
                    Paragraph(f"{sev.upper()}: {count}", self.styles["Normal"])
                )

        elements.append(Spacer(1, 0.1 * inch))
        elements.append(
            Paragraph(
                f"Total Vulnerabilities: {vuln_total}", self.styles["Normal"]
            )
        )
        if warning_total > 0:
            elements.append(
                Paragraph(
                    f"Hardening / Warnings: {warning_total} (not counted as vulnerabilities)",
                    self.styles["Normal"],
                )
            )
        if info_total > 0:
            elements.append(
                Paragraph(
                    f"Informational: {info_total} (not counted as vulnerabilities)",
                    self.styles["Normal"],
                )
            )
        if edge_total > 0:
            elements.append(
                Paragraph(
                    f"Edge Infrastructure Findings: {edge_total} "
                    "(INFO - third-party services, not counted as vulnerabilities)",
                    self.styles["Normal"],
                )
            )
        elements.append(
            Paragraph(
                f"URLs Scanned: {stats.get('urls_scanned')}", self.styles["Normal"]
            )
        )
        elements.append(
            Paragraph(
                f"Scan Duration: {stats.get('duration_seconds')} seconds",
                self.styles["Normal"],
            )
        )

        elements.append(PageBreak())

        findings = self.report_data.get("findings", [])
        warning_findings = [
            f for f in findings
            if not f.get("edge_infrastructure")
            and f.get("metadata", {}).get("classification") == "warning"
        ]
        info_findings = [
            f for f in findings
            if not f.get("edge_infrastructure")
            and f.get("metadata", {}).get("classification") != "warning"
            and f.get("severity") == "info"
        ]
        vuln_findings = [
            f for f in findings
            if not f.get("edge_infrastructure")
            and f.get("metadata", {}).get("classification") != "warning"
            and f.get("severity") != "info"
        ]
        edge_findings = [f for f in findings if f.get("edge_infrastructure")]

        # VULNERABILITIES
        elements.append(Paragraph("Vulnerabilities", self.styles["Heading1"]))
        elements.append(Spacer(1, 0.2 * inch))

        if not vuln_findings:
            elements.append(
                Paragraph(
                    "No security vulnerabilities were detected.",
                    self.styles["Normal"],
                )
            )
        else:
            for idx, finding in enumerate(vuln_findings, 1):
                elements.append(
                    Paragraph(f"{idx}. {finding['title']}", self.styles["Heading2"])
                )
                elements.append(
                    Paragraph(
                        f"Severity: {finding['severity'].upper()}",
                        self.styles["Normal"],
                    )
                )

                raw_score = finding.get("raw_risk_score", finding.get("risk_score"))

                if raw_score is not None:
                    elements.append(
                        Paragraph(
                            f"Risk Score: {raw_score}",
                            self.styles["Normal"],
                        )
                    )

                endpoints = finding.get("affected_endpoints") or [finding["url"]]
                if len(endpoints) == 1:
                    elements.append(
                        Paragraph(f"Affected URL: {endpoints[0]}", self.styles["Normal"])
                    )
                else:
                    elements.append(
                        Paragraph(
                            f"Affected Endpoints ({len(endpoints)}):",
                            self.styles["Normal"],
                        )
                    )
                    for endpoint in endpoints:
                        elements.append(Paragraph(endpoint, self.styles["Normal"]))
                elements.append(Spacer(1, 0.1 * inch))

                elements.append(Paragraph("Description", self.styles["Heading3"]))
                elements.append(
                    Paragraph(finding["description"], self.styles["Normal"])
                )
                elements.append(Spacer(1, 0.1 * inch))

                elements.append(Paragraph("Attack Scenario", self.styles["Heading3"]))
                elements.append(
                    Paragraph(
                        finding.get("attack_scenario", "Not provided."),
                        self.styles["Normal"],
                    )
                )
                elements.append(Spacer(1, 0.1 * inch))

                elements.append(Paragraph("Defense Strategy", self.styles["Heading3"]))
                elements.append(
                    Paragraph(
                        finding.get("defense_strategy", "Not provided."),
                        self.styles["Normal"],
                    )
                )
                elements.append(Spacer(1, 0.1 * inch))

                elements.append(Paragraph("Mitigation Plan", self.styles["Heading3"]))
                elements.append(
                    Paragraph(
                        finding.get("mitigation_plan", "Not provided."),
                        self.styles["Normal"],
                    )
                )
                elements.append(Spacer(1, 0.1 * inch))

                elements.append(Paragraph("Remediation", self.styles["Heading3"]))
                elements.append(
                    Paragraph(finding["remediation"], self.styles["Normal"])
                )
                elements.append(PageBreak())

        # WARNINGS
        if warning_findings:
            elements.append(Paragraph("Warnings (Informational)", self.styles["Heading1"]))
            elements.append(Spacer(1, 0.1 * inch))
            elements.append(
                Paragraph(
                    "These observations may deserve review, but the available evidence does not establish a security vulnerability.",
                    self.styles["Normal"],
                )
            )
            for idx, finding in enumerate(warning_findings, 1):
                elements.append(Paragraph(f"{idx}. {finding['title']}", self.styles["Heading2"]))
                elements.append(Paragraph(finding.get("description", ""), self.styles["Normal"]))
                elements.append(Paragraph(f"Evidence: {finding.get('evidence', {})}", self.styles["Normal"]))
                elements.append(Spacer(1, 0.1 * inch))

        # INFORMATIONAL
        if info_findings:
            elements.append(Paragraph("Informational Findings", self.styles["Heading1"]))
            elements.append(Spacer(1, 0.1 * inch))
            elements.append(
                Paragraph(
                    "Context gathered during the scan (technology fingerprints, service "
                    "banners, and similar observations). These are not vulnerabilities and "
                    "are not counted or scored.",
                    self.styles["Normal"],
                )
            )
            for idx, finding in enumerate(info_findings, 1):
                elements.append(Paragraph(f"{idx}. {finding['title']}", self.styles["Heading2"]))
                elements.append(Paragraph(finding.get("description", ""), self.styles["Normal"]))
                elements.append(Paragraph(f"Evidence: {finding.get('evidence', {})}", self.styles["Normal"]))
                elements.append(Spacer(1, 0.1 * inch))

        # EDGE INFRASTRUCTURE
        if edge_findings:
            elements.append(Paragraph("Edge Infrastructure (Informational)", self.styles["Heading1"]))
            elements.append(Spacer(1, 0.1 * inch))
            elements.append(
                Paragraph(
                    "The following findings relate to third-party edge infrastructure (CDN, reverse proxy) "
                    "that is outside your direct control. These are not vulnerabilities — they are "
                    "recorded for awareness only.",
                    self.styles["Normal"],
                )
            )
            elements.append(Spacer(1, 0.2 * inch))

            for idx, finding in enumerate(edge_findings, 1):
                elements.append(
                    Paragraph(f"{idx}. {finding['title']}", self.styles["Heading2"])
                )
                elements.append(
                    Paragraph(
                        "Category: Edge Infrastructure",
                        self.styles["Normal"],
                    )
                )
                elements.append(
                    Paragraph(
                        "Severity: INFO",
                        self.styles["Normal"],
                    )
                )
                endpoints = finding.get("affected_endpoints") or [finding["url"]]
                if len(endpoints) == 1:
                    elements.append(
                        Paragraph(f"Affected URL: {endpoints[0]}", self.styles["Normal"])
                    )
                else:
                    elements.append(
                        Paragraph(
                            f"Affected Endpoints ({len(endpoints)}):",
                            self.styles["Normal"],
                        )
                    )
                    for endpoint in endpoints:
                        elements.append(Paragraph(endpoint, self.styles["Normal"]))
                elements.append(Spacer(1, 0.1 * inch))

                elements.append(Paragraph("Description", self.styles["Heading3"]))
                elements.append(
                    Paragraph(finding["description"], self.styles["Normal"])
                )
                elements.append(Spacer(1, 0.1 * inch))
                elements.append(PageBreak())

        doc.build(elements)
        assert pdf_path.exists(), f"Failed to write {pdf_path}"
        return str(pdf_path)

"""
Reporter — Generate PDF pentest reports from session findings.
"""
import re
from datetime import datetime


def _sanitize(text: str, max_len: int = 0) -> str:
    text = str(text)
    text = re.sub(r"#{1,6}\s*", "", text)
    text = re.sub(r"\*{1,2}([^*]+)\*{1,2}", r"\1", text)
    text = re.sub(r"`{1,3}[^`]*`{1,3}", lambda m: m.group(0).replace("`", ""), text)
    replacements = {
        "\u2014": "-", "\u2013": "-", "\u2012": "-", "\u2015": "-",
        "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"',
        "\u2022": "-", "\u2026": "...", "\u00a0": " ", "\u00ae": "(R)",
        "\u00b0": " deg", "\u2192": "->", "\u2190": "<-",
    }
    for uni, asc in replacements.items():
        text = text.replace(uni, asc)
    result = []
    for ch in text:
        cp = ord(ch)
        if (32 <= cp <= 126) or (160 <= cp <= 255) or ch in "\n\r\t":
            result.append(ch)
        else:
            result.append(" ")
    text = "".join(result)
    if max_len:
        text = text[:max_len]
    return text


def generate_pdf(session: dict) -> bytes:
    from fpdf import FPDF

    target = _sanitize(session.get("target", "Unknown"))
    port = session.get("port", "")
    scan_type = _sanitize(session.get("scan_type", "Full Assessment"))
    findings = session.get("findings", [])
    recon = session.get("recon", {})
    created_at = session.get("created_at", datetime.utcnow().isoformat())[:10]

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # ---- Cover ----
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(220, 50, 50)
    pdf.cell(0, 14, "PENTEST ASSISTANT", new_x="LMARGIN", new_y="NEXT", align="C")

    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(40, 130, 220)
    pdf.cell(0, 9, f"Penetration Test Report - {scan_type}", new_x="LMARGIN", new_y="NEXT", align="C")

    pdf.ln(4)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(120, 120, 120)
    pdf.cell(0, 6, f"Target: {target}:{port}  |  Date: {created_at}", new_x="LMARGIN", new_y="NEXT", align="C")

    pdf.ln(4)
    pdf.set_fill_color(220, 50, 50)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(0, 8, "FOR AUTHORIZED SECURITY TESTING ONLY - CONFIDENTIAL", new_x="LMARGIN", new_y="NEXT", align="C", fill=True)

    # ---- Recon Summary ----
    pdf.ln(8)
    pdf.set_text_color(30, 30, 30)
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, "1. Reconnaissance Summary", new_x="LMARGIN", new_y="NEXT")

    open_ports = recon.get("open_ports", [])
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, f"Open Ports Found: {len(open_ports)}", new_x="LMARGIN", new_y="NEXT")

    os_hints = recon.get("os_hints", [])
    if os_hints:
        pdf.cell(0, 6, f"OS Guess: {os_hints[0].get('name', 'N/A')}", new_x="LMARGIN", new_y="NEXT")

    if open_ports:
        pdf.ln(3)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_fill_color(230, 230, 230)
        pdf.cell(20, 6, "Port", border=1, fill=True)
        pdf.cell(30, 6, "Service", border=1, fill=True)
        pdf.cell(0, 6, "Banner", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        for p in open_ports[:20]:
            banner = _sanitize(p.get("banner", ""), max_len=60)
            pdf.cell(20, 6, str(p["port"]), border=1)
            pdf.cell(30, 6, _sanitize(p.get("service", "unknown")), border=1)
            pdf.cell(0, 6, banner, border=1, new_x="LMARGIN", new_y="NEXT")

    # ---- Findings ----
    pdf.ln(8)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 8, "2. Findings & Payloads", new_x="LMARGIN", new_y="NEXT")

    risk_colors = {
        "CRITICAL": (220, 50, 50),
        "HIGH": (255, 140, 0),
        "MEDIUM": (200, 165, 0),
        "LOW": (0, 160, 80),
    }

    for i, finding in enumerate(findings, 1):
        pdf.add_page()
        risk = finding.get("risk", "MEDIUM").upper()
        rc, gc, bc = risk_colors.get(risk, (100, 100, 100))

        pdf.set_fill_color(rc, gc, bc)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 11)
        label = f"#{i:02d} [{risk}] {finding.get('category', '').upper()} - {finding.get('attack_type', '').upper()} - Port {finding.get('port', '')}"
        pdf.cell(0, 9, _sanitize(label), new_x="LMARGIN", new_y="NEXT", fill=True)

        pdf.set_text_color(30, 30, 30)

        # Notes
        if finding.get("notes"):
            pdf.ln(3)
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(0, 100, 180)
            pdf.cell(0, 6, "Notes", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(40, 40, 40)
            pdf.multi_cell(0, 5, _sanitize(finding.get("notes", "")))

        # Payloads
        payloads = finding.get("payloads", [])
        if payloads:
            pdf.ln(3)
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(0, 100, 180)
            pdf.cell(0, 6, "Payloads", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Courier", "", 8)
            pdf.set_text_color(20, 20, 20)
            for pl in payloads[:10]:
                payload_str = _sanitize(pl.get("payload", ""), max_len=200)
                desc = _sanitize(pl.get("description", ""), max_len=100)
                pdf.set_font("Helvetica", "B", 8)
                pdf.multi_cell(0, 5, f"[{_sanitize(pl.get('type', ''))}] {desc}")
                pdf.set_font("Courier", "", 8)
                pdf.set_fill_color(245, 245, 245)
                pdf.multi_cell(0, 5, payload_str, fill=True)
                pdf.ln(1)

        # Tools
        tools = finding.get("tools", [])
        if tools:
            pdf.ln(3)
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(0, 100, 180)
            pdf.cell(0, 6, "Recommended Tools / Commands", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Courier", "", 8)
            pdf.set_text_color(40, 40, 40)
            for t in tools:
                pdf.multi_cell(0, 5, _sanitize(t, max_len=200))

        # Manual steps
        steps = finding.get("manual_steps", [])
        if steps:
            pdf.ln(3)
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(0, 100, 180)
            pdf.cell(0, 6, "Manual Steps", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(40, 40, 40)
            for j, step in enumerate(steps, 1):
                pdf.multi_cell(0, 5, f"{j}. {_sanitize(step, max_len=200)}")

    # Footer page
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 8, "3. Disclaimer", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(0, 6,
        "This report was generated by Pentest Assistant for authorized security testing purposes only. "
        "All testing must be performed with explicit written permission from the target system owner. "
        "Unauthorized use of this information is illegal and unethical.")

    raw = pdf.output()
    return bytes(raw) if raw else b""

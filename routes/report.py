import os
from datetime import datetime

from flask import Blueprint, g, render_template, request, send_from_directory

from database import (
    get_security_reports,
    log_activity,
    save_scan_history,
    save_security_report,
)

report_bp = Blueprint("report", __name__)


def build_pdf_report(title, risk_score, explanation, recommendations):
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    safe_title = title.replace(" ", "_")
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports", f"{safe_title}_{datetime.now(tz=datetime.timezone.utc).strftime('%Y%m%d%H%M%S')}.pdf")
    c = canvas.Canvas(path, pagesize=letter)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(40, 760, "SafeLink AI Security Report")
    c.setFont("Helvetica", 11)
    c.drawString(40, 730, f"Title: {title}")
    c.drawString(40, 710, f"Risk Score: {risk_score}")
    c.drawString(40, 690, "AI Explanation:")
    text = c.beginText(40, 670)
    for line in explanation.splitlines() or [explanation]:
        text.textLine(line[:90])
    c.drawText(text)
    c.drawString(40, 620, "Recommendations:")
    text2 = c.beginText(40, 600)
    for item in recommendations:
        text2.textLine(f"- {item}")
    c.drawText(text2)
    c.save()
    return path


@report_bp.route("/reports")
def reports():
    rows = get_security_reports(g.user["id"])
    return render_template("reports.html", reports=rows, title="Security Reports")


@report_bp.route("/generate-report", methods=["GET", "POST"])
def generate_report():
    if request.method == "POST":
        title = request.form.get("title", "Security Assessment")
        risk_score = request.form.get("risk_score", "75")
        explanation = request.form.get("explanation", "High-risk item requires immediate review.")
        recommendations = [item.strip() for item in request.form.get("recommendations", "Review the destination, avoid credentials, use layered protection").split(",") if item.strip()]
        try:
            report_path = build_pdf_report(title, risk_score, explanation, recommendations)
        except (ImportError, OSError):
            report_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports", f"{title.replace(' ', '_')}.txt")
            with open(report_path, "w", encoding="utf-8") as handle:
                handle.write(f"{title}\nRisk Score: {risk_score}\nExplanation: {explanation}\nRecommendations: {', '.join(recommendations)}")
        save_security_report(g.user["id"], "assessment", title, report_path, explanation)
        save_scan_history(g.user["id"], "report", title, "Generated", "Safe", int(risk_score), {"path": report_path})
        log_activity(g.user["id"], "generate_report", title)
        return render_template("reports.html", reports=get_security_reports(g.user["id"]), title="Security Reports")
    return render_template("reports.html", reports=get_security_reports(g.user["id"]), title="Security Reports")


@report_bp.route("/download-report/<path:filename>")
def download_report(filename):
    return send_from_directory(os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports"), filename, as_attachment=True)

from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from models import ScanSession

TEMPLATE_DIR = Path(__file__).parent.parent / "templates"
env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)


def generate_html_report(session: ScanSession) -> str:
    template = env.get_template("report.html.j2")
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}

    sorted_findings = sorted(
        session.va_findings,
        key=lambda f: severity_order.get(f.severity, 99),
    )

    pt_map = {r.finding_id: r for r in session.pt_results}
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for f in sorted_findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    confirmed = sum(1 for r in session.pt_results if r.status == "confirmed")
    false_pos = sum(1 for r in session.pt_results if r.status == "false_positive")
    inconclusive = sum(1 for r in session.pt_results if r.status == "inconclusive")

    return template.render(
        session=session,
        findings=sorted_findings,
        pt_map=pt_map,
        severity_counts=severity_counts,
        confirmed=confirmed,
        false_pos=false_pos,
        inconclusive=inconclusive,
        narrative=session.narrative,
    )

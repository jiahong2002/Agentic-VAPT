import { getReportUrl, getReportDownloadUrl } from "../api";

export default function ReportViewer({ sessionId }) {
  const reportUrl = getReportUrl(sessionId);
  const downloadUrl = getReportDownloadUrl(sessionId);

  return (
    <div>
      <div className="card">
        <h2 className="card-title">VAPT Report Ready</h2>
        <p className="card-desc">
          The Codex agent has compiled the full Vulnerability Assessment and
          Penetration Testing report. Review it below or download it.
        </p>
        <div className="report-actions">
          <a href={downloadUrl} download className="btn btn-primary">
            Download HTML Report
          </a>
          <a href={reportUrl} target="_blank" rel="noreferrer" className="btn btn-ghost">
            Open in new tab
          </a>
        </div>
      </div>
      <div className="report-frame-wrapper">
        <iframe
          src={reportUrl}
          title="VAPT Report"
          className="report-frame"
          sandbox="allow-same-origin"
        />
      </div>
    </div>
  );
}

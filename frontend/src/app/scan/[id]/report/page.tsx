'use client';

import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import styles from './report.module.css';

type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

interface SASTFinding {
  id: string;
  title: string;
  file_path: string;
  line_number?: number;
  technique: string;
  severity: Severity;
  description: string;
  code_snippet: string;
  patch: string;
  explanation: string;
}

function severityClass(s: Severity) {
  return `badge badge-${s.toLowerCase()}`;
}

function DiffBlock({ patch }: { patch: string }) {
  return (
    <div className={styles.diffBlock}>
      {patch.split('\n').map((line, i) => {
        let cls = styles.diffLine;
        if (line.startsWith('+') && !line.startsWith('+++')) cls = `${styles.diffLine} ${styles.lineAdded}`;
        else if (line.startsWith('-') && !line.startsWith('---')) cls = `${styles.diffLine} ${styles.lineRemoved}`;
        else if (line.startsWith('@@')) cls = `${styles.diffLine} ${styles.lineHunk}`;
        return <div key={i} className={cls}>{line || ' '}</div>;
      })}
    </div>
  );
}

function SASTFindingCard({ finding }: { finding: SASTFinding }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div className={styles.sastCard}>
      <div className={styles.sastCardHeader}>
        <span className={severityClass(finding.severity)}>{finding.severity}</span>
        <span className={styles.sastTitle}>{finding.title}</span>
        <span className={styles.sastTechnique}>{finding.technique}</span>
      </div>
      <div className={styles.sastFile}>
        {finding.file_path}{finding.line_number ? `:${finding.line_number}` : ''}
      </div>
      <p className={styles.sastDesc}>{finding.description}</p>
      {finding.patch && (
        <button className={styles.diffToggle} onClick={() => setExpanded(p => !p)}>
          {expanded ? '▲ Hide patch' : '▼ Show patch'}
        </button>
      )}
      {expanded && finding.patch && <DiffBlock patch={finding.patch} />}
      {expanded && finding.explanation && (
        <p className={styles.sastExplanation}>{finding.explanation}</p>
      )}
    </div>
  );
}

export default function ReportPage() {
  const { id: scanId } = useParams<{ id: string }>();
  const router = useRouter();

  const [activeTab, setActiveTab] = useState<'report' | 'sast'>('report');
  const [sastFindings, setSastFindings] = useState<SASTFinding[]>([]);
  const [sastStatus, setSastStatus] = useState<string>('PENDING');
  const [hasSast, setHasSast] = useState(false);

  const pdfUrl = `http://localhost:8000/api/scan/${scanId}/report/pdf`;

  useEffect(() => {
    if (!scanId) return;
    fetch(`http://localhost:8000/api/scan/${scanId}/sast-findings`)
      .then(r => r.json())
      .then(data => {
        if (data.findings && data.findings.length > 0) {
          setSastFindings(data.findings);
          setHasSast(true);
        }
        setSastStatus(data.status || 'PENDING');
      })
      .catch(() => {});
  }, [scanId]);

  const handleDownload = () => {
    const a = document.createElement('a');
    a.href = pdfUrl;
    a.download = `pentest-report-${String(scanId).slice(0, 8)}.pdf`;
    a.click();
  };

  return (
    <div className={styles.page}>
      <div className={styles.toolbar}>
        <button className={styles.backBtn} onClick={() => router.back()}>← Back</button>
        <div className={styles.tabBar}>
          <button
            className={`${styles.tab} ${activeTab === 'report' ? styles.tabActive : ''}`}
            onClick={() => setActiveTab('report')}
          >
            DAST Report
          </button>
          <button
            className={`${styles.tab} ${activeTab === 'sast' ? styles.tabActive : ''}`}
            onClick={() => setActiveTab('sast')}
          >
            SAST Findings
            {hasSast && <span className={styles.tabBadge}>{sastFindings.length}</span>}
          </button>
        </div>
        <button className={styles.pdfBtn} onClick={handleDownload}>
          ⬇ Download PDF
        </button>
      </div>

      {activeTab === 'report' && (
        <iframe
          className={styles.viewer}
          src={pdfUrl}
          title="Security Assessment Report"
        />
      )}

      {activeTab === 'sast' && (
        <div className={styles.sastPanel}>
          {!hasSast && sastStatus === 'PENDING' && (
            <div className={styles.emptyState}>
              No SAST analysis was run for this scan.<br />
              Start a new scan with SAST or Both mode to see static findings.
            </div>
          )}
          {!hasSast && sastStatus === 'RUNNING' && (
            <div className={styles.emptyState}>
              SAST analysis is still running — check back shortly.
            </div>
          )}
          {!hasSast && sastStatus === 'ERROR' && (
            <div className={styles.emptyState} style={{ color: '#ef4444' }}>
              SAST analysis encountered an error. Check the scan dashboard for details.
            </div>
          )}
          {!hasSast && sastStatus === 'DONE' && (
            <div className={styles.emptyState}>
              No security vulnerabilities were identified in the static analysis.
            </div>
          )}
          {hasSast && (
            <>
              <div className={styles.sastHeader}>
                <span className={styles.sastHeaderTitle}>Static Analysis Findings</span>
                <span className={styles.sastHeaderCount}>{sastFindings.length} issue{sastFindings.length !== 1 ? 's' : ''}</span>
              </div>
              <div className={styles.sastList}>
                {sastFindings.map(f => (
                  <SASTFindingCard key={f.id} finding={f} />
                ))}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}

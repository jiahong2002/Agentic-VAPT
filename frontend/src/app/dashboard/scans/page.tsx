'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { apiFetch } from '../../../lib/auth';
import styles from './page.module.css';

interface Scan {
  id: string;
  target_url: string;
  status: string;
  report_pdf_url: string | null;
  created_at: string;
  updated_at: string;
}

const STATUS_LABELS: Record<string, string> = {
  CRAWLING: 'Crawling',
  SCANNING: 'Scanning',
  AWAITING_APPROVAL: 'Awaiting Approval',
  EXPLOITING: 'Exploiting',
  DONE: 'Done',
  ERROR: 'Error',
};

const STATUS_CLASS: Record<string, string> = {
  CRAWLING: 'running',
  SCANNING: 'running',
  AWAITING_APPROVAL: 'waiting',
  EXPLOITING: 'running',
  DONE: 'done',
  ERROR: 'error',
};

function formatDate(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleString(undefined, {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

function truncateUrl(url: string, max = 48): string {
  try {
    const u = new URL(url);
    const display = u.hostname + (u.pathname !== '/' ? u.pathname : '');
    return display.length > max ? display.slice(0, max) + '…' : display;
  } catch {
    return url.length > max ? url.slice(0, max) + '…' : url;
  }
}

export default function ScansPage() {
  const router = useRouter();
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    apiFetch('/api/scans')
      .then(res => {
        if (!res.ok) throw new Error('Failed to load scans');
        return res.json();
      })
      .then(data => setScans(data.scans ?? []))
      .catch(err => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className={styles.page}>
      <div className={styles.container}>
        <div className={styles.header}>
          <div>
            <h1 className={styles.title}>Scan History</h1>
            <p className={styles.subtitle}>Your previous penetration tests</p>
          </div>
          <button className={styles.newBtn} onClick={() => router.push('/dashboard')}>
            + New Scan
          </button>
        </div>

        {loading && (
          <div className={styles.stateBox}>
            <span className={styles.loadingDot} />
            <span className={styles.stateText}>Loading scans...</span>
          </div>
        )}

        {!loading && error && (
          <div className={styles.errorBox}>{error}</div>
        )}

        {!loading && !error && scans.length === 0 && (
          <div className={styles.emptyBox}>
            <div className={styles.emptyIcon}>⌖</div>
            <div className={styles.emptyTitle}>No scans yet</div>
            <div className={styles.emptyDesc}>Start your first penetration test from the dashboard.</div>
          </div>
        )}

        {!loading && !error && scans.length > 0 && (
          <div className={styles.tableWrap}>
            <table className={styles.table}>
              <thead>
                <tr>
                  <th className={styles.th}>Target</th>
                  <th className={styles.th}>Status</th>
                  <th className={styles.th}>Date</th>
                  <th className={styles.th}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {scans.map(scan => (
                  <tr key={scan.id} className={styles.row}>
                    <td className={styles.td}>
                      <span className={styles.targetUrl} title={scan.target_url}>
                        {truncateUrl(scan.target_url)}
                      </span>
                    </td>
                    <td className={styles.td}>
                      <span className={`${styles.badge} ${styles[`badge_${STATUS_CLASS[scan.status] ?? 'running'}`]}`}>
                        {STATUS_LABELS[scan.status] ?? scan.status}
                      </span>
                    </td>
                    <td className={styles.td}>
                      <span className={styles.dateText}>{formatDate(scan.created_at)}</span>
                    </td>
                    <td className={styles.td}>
                      <div className={styles.actions}>
                        {scan.status === 'DONE' && (
                          <button
                            className={styles.actionBtn}
                            onClick={() => router.push(`/scan/${scan.id}/report`)}
                          >
                            View Report
                          </button>
                        )}
                        {scan.status !== 'DONE' && scan.status !== 'ERROR' && (
                          <button
                            className={styles.actionBtn}
                            onClick={() => router.push(`/scan/${scan.id}`)}
                          >
                            View Live
                          </button>
                        )}
                        {scan.report_pdf_url && (
                          <a
                            className={`${styles.actionBtn} ${styles.actionBtnPdf}`}
                            href={scan.report_pdf_url}
                            target="_blank"
                            rel="noopener noreferrer"
                          >
                            PDF
                          </a>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

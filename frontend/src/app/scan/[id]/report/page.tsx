'use client';

import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import styles from './report.module.css';
import { apiFetch } from '../../../../lib/auth';

export default function ReportPage() {
  const { id: scanId } = useParams<{ id: string }>();
  const router = useRouter();
  const [reportSrc, setReportSrc] = useState('');

  useEffect(() => {
    apiFetch(`/api/scan/${scanId}/report`)
      .then(r => r.text())
      .then(html => {
        const blob = new Blob([html], { type: 'text/html' });
        setReportSrc(URL.createObjectURL(blob));
      });
  }, [scanId]);

  const handleDownload = async () => {
    const res = await apiFetch(`/api/scan/${scanId}/report/pdf`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `pentest-report-${String(scanId).slice(0, 8)}.pdf`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className={styles.page}>
      <div className={styles.toolbar}>
        <button className={styles.backBtn} onClick={() => router.back()}>← Back</button>
        <span className={styles.title}>Security Assessment Report</span>
        <button className={styles.pdfBtn} onClick={handleDownload}>
          ⬇ Download PDF
        </button>
      </div>
      <iframe
        className={styles.viewer}
        src={reportSrc}
        title="Security Assessment Report"
      />
    </div>
  );
}

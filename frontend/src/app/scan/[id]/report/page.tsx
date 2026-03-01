'use client';

import { useParams, useRouter } from 'next/navigation';
import styles from './report.module.css';

export default function ReportPage() {
  const { id: scanId } = useParams<{ id: string }>();
  const router = useRouter();

  const pdfUrl = `http://localhost:8000/api/scan/${scanId}/report/pdf`;

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
        <span className={styles.title}>Security Assessment Report</span>
        <button className={styles.pdfBtn} onClick={handleDownload}>
          ⬇ Download PDF
        </button>
      </div>
      <iframe
        className={styles.viewer}
        src={pdfUrl}
        title="Security Assessment Report"
      />
    </div>
  );
}

'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { apiFetch } from '../../lib/auth';
import styles from './page.module.css';

export default function DashboardPage() {
  const router = useRouter();
  const [url, setUrl] = useState('');
  const [agreed, setAgreed] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // SAST state
  const [sastEnabled, setSastEnabled] = useState(false);
  const [repoUrl, setRepoUrl] = useState('');
  const [pat, setPat] = useState('');

  // Deep scan state
  const [deepScanEnabled, setDeepScanEnabled] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!agreed) { setError('You must confirm authorization to proceed.'); return; }
    if (!url.trim()) { setError('Please enter a target URL.'); return; }
    if (sastEnabled && !repoUrl.trim()) { setError('Please enter a GitHub repository URL for SAST.'); return; }
    setError('');
    setLoading(true);

    const body: Record<string, unknown> = { url: url.trim(), deep_scan: deepScanEnabled };
    if (sastEnabled) {
      body.sast_config = {
        repo_url: repoUrl.trim(),
        pat: pat.trim() || null,
      };
    }

    try {
      const res = await apiFetch('/api/scan/start', {
        method: 'POST',
        body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error('Failed to start scan');
      const { scan_id } = await res.json();
      router.push(`/scan/${scan_id}`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to connect to backend');
      setLoading(false);
    }
  };

  return (
    <div className={styles.page}>
      <div className={styles.container}>
        <div className={styles.header}>
          <h1 className={styles.title}>New Penetration Test</h1>
          <p className={styles.subtitle}>
            Enter a target URL to begin. AI agents will crawl, analyze, and attempt to exploit vulnerabilities.
          </p>
        </div>

        <div className={styles.card}>
          <form onSubmit={handleSubmit} className={styles.form}>

            {/* ── Target URL ── */}
            <div className={styles.fieldGroup}>
              <label className={styles.label} htmlFor="target-url">Target URL</label>
              <div className={styles.inputWrapper}>
                <span className={styles.inputIcon}>⌖</span>
                <input
                  id="target-url"
                  type="url"
                  className={styles.input}
                  placeholder="https://target.example.com"
                  value={url}
                  onChange={e => setUrl(e.target.value)}
                  disabled={loading}
                  required
                />
              </div>
            </div>

            {/* ── Pipeline overview ── */}
            <div className={styles.phases}>
              <div className={styles.phaseItem}>
                <span className={styles.phaseNum}>01</span>
                <div>
                  <div className={styles.phaseName}>Crawl &amp; Scan</div>
                  <div className={styles.phaseDesc}>Maps attack surface, audits headers</div>
                </div>
              </div>
              <div className={styles.phaseDivider} />
              <div className={styles.phaseItem}>
                <span className={styles.phaseNum}>02</span>
                <div>
                  <div className={styles.phaseName}>Recon Agent</div>
                  <div className={styles.phaseDesc}>Generates attack hypotheses</div>
                </div>
              </div>
              <div className={styles.phaseDivider} />
              <div className={styles.phaseItem}>
                <span className={styles.phaseNum}>03</span>
                <div>
                  <div className={styles.phaseName}>Exploit Agents</div>
                  <div className={styles.phaseDesc}>Confirms vulns with PoC + screenshots</div>
                </div>
              </div>
            </div>

            {/* ── Optional SAST ── */}
            <div className={styles.sastSection}>
              <button
                type="button"
                className={styles.sastToggle}
                onClick={() => setSastEnabled(v => !v)}
                disabled={loading}
              >
                <span className={`${styles.sastToggleIcon} ${sastEnabled ? styles.sastToggleIconOn : ''}`}>
                  {sastEnabled ? '▾' : '▸'}
                </span>
                <span className={styles.sastToggleLabel}>
                  Static Analysis (SAST)
                  <span className={styles.sastBadge}>Optional</span>
                </span>
                <span className={styles.sastToggleDesc}>
                  {sastEnabled ? 'Enabled — Semgrep will scan your source code' : 'Add source code scanning via Semgrep'}
                </span>
              </button>

              {sastEnabled && (
                <div className={styles.sastFields}>
                  <div className={styles.fieldGroup}>
                    <label className={styles.label} htmlFor="repo-url">GitHub Repository URL</label>
                    <div className={styles.inputWrapper}>
                      <span className={styles.inputIcon}>⌥</span>
                      <input
                        id="repo-url"
                        type="url"
                        className={styles.input}
                        placeholder="https://github.com/username/repo"
                        value={repoUrl}
                        onChange={e => setRepoUrl(e.target.value)}
                        disabled={loading}
                      />
                    </div>
                  </div>
                  <div className={styles.fieldGroup}>
                    <label className={styles.label} htmlFor="github-pat">
                      GitHub Personal Access Token
                      <span className={styles.fieldOptional}>optional — for private repos</span>
                    </label>
                    <div className={styles.inputWrapper}>
                      <span className={styles.inputIcon}>⚿</span>
                      <input
                        id="github-pat"
                        type="password"
                        className={styles.input}
                        placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
                        value={pat}
                        onChange={e => setPat(e.target.value)}
                        disabled={loading}
                        autoComplete="off"
                      />
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* ── Deep Scan ── */}
            <div className={styles.deepSection}>
              <button
                type="button"
                className={styles.deepToggle}
                onClick={() => setDeepScanEnabled(v => !v)}
                disabled={loading}
              >
                <span className={styles.deepToggleLabel}>
                  Deep Scan
                  <span className={styles.deepBadge}>Slow</span>
                </span>
                <span className={styles.deepToggleDesc}>
                  {deepScanEnabled
                    ? 'Depth 3 crawl + full Nuclei template coverage'
                    : 'Depth 2 crawl, curated templates (faster)'}
                </span>
                <div className={`${styles.deepSwitch} ${deepScanEnabled ? styles.deepSwitchOn : ''}`}>
                  <div className={`${styles.deepKnob} ${deepScanEnabled ? styles.deepKnobOn : ''}`} />
                </div>
              </button>
            </div>

            {/* ── Authorization ── */}
            <label className={styles.authLabel}>
              <input
                type="checkbox"
                className={styles.checkbox}
                checked={agreed}
                onChange={e => setAgreed(e.target.checked)}
                disabled={loading}
                id="auth-confirm"
              />
              <span>
                I confirm I have <strong>written authorization</strong> to test this target and take full legal responsibility for this scan.
              </span>
            </label>

            {error && <div className={styles.errorMsg}>{error}</div>}

            <button
              id="start-scan-btn"
              type="submit"
              className={styles.cta}
              disabled={loading || !agreed}
            >
              {loading ? (
                <><span className={styles.spinner} /> Starting scan...</>
              ) : (
                <>Launch {deepScanEnabled ? 'Deep ' : ''}{sastEnabled ? 'DAST + SAST' : 'Scan'} <span className={styles.arrow}>→</span></>
              )}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}

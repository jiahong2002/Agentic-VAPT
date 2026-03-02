'use client';

import { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import styles from './page.module.css';

// ─── Network Topology Canvas ─────────────────────────────────────────────────
interface Node {
  x: number; y: number;
  vx: number; vy: number;
  radius: number;
  hue: number;
  pulse: number;
  pulseSpeed: number;
}

function NetworkCanvas({ triggered }: { triggered: boolean }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const mouse = useRef({ x: -1000, y: -1000 });
  const nodesRef = useRef<Node[]>([]);
  const animRef = useRef<number>(0);
  const triggerRef = useRef(triggered);

  useEffect(() => { triggerRef.current = triggered; }, [triggered]);

  useEffect(() => {
    const canvas = canvasRef.current!;
    const ctx = canvas.getContext('2d')!;

    const resize = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    };
    resize();
    window.addEventListener('resize', resize);

    // Create nodes
    const N = 90;
    nodesRef.current = Array.from({ length: N }, () => ({
      x: Math.random() * canvas.width,
      y: Math.random() * canvas.height,
      vx: (Math.random() - 0.5) * 0.4,
      vy: (Math.random() - 0.5) * 0.4,
      radius: 2 + Math.random() * 2.5,
      hue: 180 + Math.random() * 60, // cyan-ish
      pulse: Math.random() * Math.PI * 2,
      pulseSpeed: 0.02 + Math.random() * 0.02,
    }));

    const onMouseMove = (e: MouseEvent) => {
      mouse.current = { x: e.clientX, y: e.clientY };
    };
    window.addEventListener('mousemove', onMouseMove);

    let scanRed = 0;

    const draw = () => {
      const W = canvas.width, H = canvas.height;
      ctx.clearRect(0, 0, W, H);

      // Background gradient
      const bg = ctx.createRadialGradient(W / 2, H / 2, 0, W / 2, H / 2, Math.max(W, H) * 0.8);
      bg.addColorStop(0, 'rgba(6,20,40,1)');
      bg.addColorStop(1, 'rgba(4,8,16,1)');
      ctx.fillStyle = bg;
      ctx.fillRect(0, 0, W, H);

      if (triggerRef.current) {
        scanRed = Math.min(scanRed + 0.015, 1);
      }

      const nodes = nodesRef.current;
      const mx = mouse.current.x, my = mouse.current.y;

      // Update node positions
      nodes.forEach(n => {
        // Mouse gravity
        const dx = mx - n.x, dy = my - n.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 180) {
          const force = (180 - dist) / 180 * 0.06;
          n.vx += dx / dist * force;
          n.vy += dy / dist * force;
        }

        n.vx *= 0.97; n.vy *= 0.97;
        n.x += n.vx; n.y += n.vy;
        n.pulse += n.pulseSpeed;

        // Bounce
        if (n.x < 0 || n.x > W) n.vx *= -1;
        if (n.y < 0 || n.y > H) n.vy *= -1;
        n.x = Math.max(0, Math.min(W, n.x));
        n.y = Math.max(0, Math.min(H, n.y));
      });

      // Draw edges
      const maxDist = 160;
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const a = nodes[i], b = nodes[j];
          const dx = a.x - b.x, dy = a.y - b.y;
          const d = Math.sqrt(dx * dx + dy * dy);
          if (d < maxDist) {
            const alpha = (1 - d / maxDist) * 0.35;
            const h = scanRed > 0 ? `${Math.round(a.hue * (1 - scanRed))}` : `${a.hue}`;
            const r = scanRed > 0 ? Math.round(scanRed * 200) : 6;
            const g = scanRed > 0 ? Math.round((1 - scanRed) * 182) : 182;
            const bl = scanRed > 0 ? Math.round((1 - scanRed) * 212) : 212;
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.strokeStyle = `rgba(${r},${g},${bl},${alpha})`;
            ctx.lineWidth = 0.8;
            ctx.stroke();
          }
        }
      }

      // Draw nodes
      nodes.forEach(n => {
        const pulseMag = 0.5 + 0.5 * Math.sin(n.pulse);
        const r = scanRed > 0 ? Math.round(220 * scanRed + 6 * (1 - scanRed)) : 6;
        const g = scanRed > 0 ? Math.round(30 * scanRed + 182 * (1 - scanRed)) : 182;
        const bl = scanRed > 0 ? Math.round(30 * scanRed + 212 * (1 - scanRed)) : 212;

        // Glow
        const grd = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, n.radius * 6);
        grd.addColorStop(0, `rgba(${r},${g},${bl},${0.15 * pulseMag})`);
        grd.addColorStop(1, 'rgba(0,0,0,0)');
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.radius * 6, 0, Math.PI * 2);
        ctx.fillStyle = grd;
        ctx.fill();

        // Core dot
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.radius * pulseMag, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(${r},${g},${bl},0.9)`;
        ctx.fill();
      });

      animRef.current = requestAnimationFrame(draw);
    };

    draw();

    return () => {
      cancelAnimationFrame(animRef.current);
      window.removeEventListener('resize', resize);
      window.removeEventListener('mousemove', onMouseMove);
    };
  }, []);

  return <canvas ref={canvasRef} className={styles.canvas} />;
}


type ScanMode = 'DAST' | 'SAST' | 'BOTH';

const MODE_LABELS: Record<ScanMode, string> = {
  DAST: 'DAST',
  SAST: 'SAST',
  BOTH: 'Both',
};
const MODE_DESCRIPTIONS: Record<ScanMode, string> = {
  DAST: 'Dynamic — exploit a live target',
  SAST: 'Static — audit your source code',
  BOTH: 'Dynamic + static in parallel',
};

// ─── Home Page ───────────────────────────────────────────────────────────────
export default function HomePage() {
  const router = useRouter();
  const [mode, setMode] = useState<ScanMode>('DAST');
  const [url, setUrl] = useState('');
  const [githubPat, setGithubPat] = useState('');
  const [githubRepo, setGithubRepo] = useState('');
  const [agreed, setAgreed] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [triggered, setTriggered] = useState(false);

  const needsUrl = mode === 'DAST' || mode === 'BOTH';
  const needsGithub = mode === 'SAST' || mode === 'BOTH';

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!agreed) { setError('You must confirm authorization to proceed.'); return; }
    if (needsUrl && !url.trim()) { setError('Please enter a target URL.'); return; }
    if (needsGithub && !githubPat.trim()) { setError('Please enter your GitHub PAT.'); return; }
    if (needsGithub && !githubRepo.trim().includes('/')) {
      setError("GitHub repo must be in 'owner/repo' format.");
      return;
    }
    setError('');
    setTriggered(true);
    setLoading(true);

    try {
      const body: Record<string, string> = { mode };
      if (needsUrl) body.url = url.trim();
      if (needsGithub) {
        body.github_pat = githubPat.trim();
        body.github_repo = githubRepo.trim();
      }

      const res = await fetch('http://localhost:8000/api/scan/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.detail || 'Failed to start scan');
      }
      const { scan_id } = await res.json();
      await new Promise(r => setTimeout(r, 800));
      router.push(`/scan/${scan_id}`);
    } catch (err: any) {
      setError(err.message || 'Failed to connect to backend');
      setLoading(false);
      setTriggered(false);
    }
  };

  return (
    <main className={styles.main}>
      <NetworkCanvas triggered={triggered} />

      <div className={styles.overlay}>
        <div className={styles.hero}>
          <div className={styles.tag}>
            <span className={styles.tagDot} />
            AGENTIC PENETRATION TESTING
          </div>

          <h1 className={styles.headline}>
            Uncover What<br />
            <span className={styles.accentText}>Attackers See</span>
          </h1>

          <p className={styles.subheadline}>
            AI agents crawl your target, generate attack hypotheses — including zero-days —
            verify each one, and deliver a full PoC report with screenshots.
          </p>

          <form className={styles.form} onSubmit={handleSubmit}>
            {/* Mode selector */}
            <div className={styles.modeSelector}>
              {(['DAST', 'SAST', 'BOTH'] as ScanMode[]).map(m => (
                <button
                  key={m}
                  type="button"
                  className={`${styles.modeTab} ${mode === m ? styles.modeTabActive : ''}`}
                  onClick={() => { setMode(m); setError(''); }}
                  disabled={loading}
                >
                  <span className={styles.modeTabLabel}>{MODE_LABELS[m]}</span>
                  <span className={styles.modeTabDesc}>{MODE_DESCRIPTIONS[m]}</span>
                </button>
              ))}
            </div>

            {/* Target URL — shown for DAST / Both */}
            {needsUrl && (
              <div className={styles.inputRow}>
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
                  />
                </div>
              </div>
            )}

            {/* GitHub fields — shown for SAST / Both */}
            {needsGithub && (
              <div className={styles.githubSection}>
                <div className={styles.githubRow}>
                  <div className={styles.inputWrapper}>
                    <span className={styles.inputIcon} style={{ fontSize: 14 }}>&#x1F511;</span>
                    <input
                      id="github-pat"
                      type="password"
                      className={styles.input}
                      placeholder="GitHub Personal Access Token (repo scope)"
                      value={githubPat}
                      onChange={e => setGithubPat(e.target.value)}
                      disabled={loading}
                      autoComplete="off"
                    />
                  </div>
                </div>
                <div className={styles.githubRow}>
                  <div className={styles.inputWrapper}>
                    <span className={styles.inputIcon} style={{ fontSize: 14 }}>&#x1F4C1;</span>
                    <input
                      id="github-repo"
                      type="text"
                      className={styles.input}
                      placeholder="owner/repository"
                      value={githubRepo}
                      onChange={e => setGithubRepo(e.target.value)}
                      disabled={loading}
                    />
                  </div>
                </div>
              </div>
            )}

            <button
              id="start-scan-btn"
              type="submit"
              className={styles.cta}
              disabled={loading || !agreed}
            >
              {loading ? (
                <span className={styles.spinner} />
              ) : (
                <>Start Scan <span className={styles.arrow}>→</span></>
              )}
            </button>

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
                I confirm I have written authorization to test this target and take full legal responsibility for this scan.
              </span>
            </label>

            {error && <div className={styles.errorMsg}>{error}</div>}
          </form>

          <div className={styles.stats}>
            <div className={styles.statItem}>
              <span className={styles.statNum}>∞</span>
              <span className={styles.statLabel}>Vuln Types</span>
            </div>
            <div className={styles.statDivider} />
            <div className={styles.statItem}>
              <span className={styles.statNum}>↦↦</span>
              <span className={styles.statLabel}>Parallel Agents</span>
            </div>
            <div className={styles.statDivider} />
            <div className={styles.statItem}>
              <span className={styles.statNum}>PoC</span>
              <span className={styles.statLabel}>Screenshot Report</span>
            </div>
          </div>
        </div>
      </div>
    </main>
  );
}

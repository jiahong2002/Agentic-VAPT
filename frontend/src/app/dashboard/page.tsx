'use client';

import { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import styles from './page.module.css';
import { apiFetch, logout, getUsername } from '../../lib/auth';

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

    const N = 90;
    nodesRef.current = Array.from({ length: N }, () => ({
      x: Math.random() * canvas.width,
      y: Math.random() * canvas.height,
      vx: (Math.random() - 0.5) * 0.4,
      vy: (Math.random() - 0.5) * 0.4,
      radius: 2 + Math.random() * 2.5,
      hue: 180 + Math.random() * 60,
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

      nodes.forEach(n => {
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

        if (n.x < 0 || n.x > W) n.vx *= -1;
        if (n.y < 0 || n.y > H) n.vy *= -1;
        n.x = Math.max(0, Math.min(W, n.x));
        n.y = Math.max(0, Math.min(H, n.y));
      });

      const maxDist = 160;
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const a = nodes[i], b = nodes[j];
          const dx = a.x - b.x, dy = a.y - b.y;
          const d = Math.sqrt(dx * dx + dy * dy);
          if (d < maxDist) {
            const alpha = (1 - d / maxDist) * 0.35;
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

      nodes.forEach(n => {
        const pulseMag = 0.5 + 0.5 * Math.sin(n.pulse);
        const r = scanRed > 0 ? Math.round(220 * scanRed + 6 * (1 - scanRed)) : 6;
        const g = scanRed > 0 ? Math.round(30 * scanRed + 182 * (1 - scanRed)) : 182;
        const bl = scanRed > 0 ? Math.round(30 * scanRed + 212 * (1 - scanRed)) : 212;

        const grd = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, n.radius * 6);
        grd.addColorStop(0, `rgba(${r},${g},${bl},${0.15 * pulseMag})`);
        grd.addColorStop(1, 'rgba(0,0,0,0)');
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.radius * 6, 0, Math.PI * 2);
        ctx.fillStyle = grd;
        ctx.fill();

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


// ─── Dashboard Page ───────────────────────────────────────────────────────────
export default function DashboardPage() {
  const router = useRouter();
  const [url, setUrl] = useState('');
  const [agreed, setAgreed] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [triggered, setTriggered] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!agreed) { setError('You must confirm authorization to proceed.'); return; }
    if (!url.trim()) { setError('Please enter a target URL.'); return; }
    setError('');
    setTriggered(true);
    setLoading(true);

    try {
      const res = await apiFetch('/api/scan/start', {
        method: 'POST',
        body: JSON.stringify({ url: url.trim() }),
      });
      if (!res.ok) throw new Error('Failed to start scan');
      const { scan_id } = await res.json();
      await new Promise(r => setTimeout(r, 800));
      router.push(`/scan/${scan_id}`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to connect to backend');
      setLoading(false);
      setTriggered(false);
    }
  };

  return (
    <main className={styles.main}>
      <NetworkCanvas triggered={triggered} />

      <div className={styles.overlay}>
        <div className={styles.hero}>
          <div className={styles.userBar}>
            <span className={styles.userBarName}>{getUsername()}</span>
            <button className={styles.logoutBtn} onClick={logout}>Sign out</button>
          </div>

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
                  required
                />
              </div>
              <button
                id="start-scan-btn"
                type="submit"
                className={styles.cta}
                disabled={loading || !agreed}
              >
                {loading ? (
                  <span className={styles.spinner} />
                ) : (
                  <>Scan Target <span className={styles.arrow}>→</span></>
                )}
              </button>
            </div>

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

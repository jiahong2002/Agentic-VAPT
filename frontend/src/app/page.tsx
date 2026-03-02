'use client';

import { useEffect, useRef } from 'react';
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

function NetworkCanvas() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const mouse = useRef({ x: -1000, y: -1000 });
  const nodesRef = useRef<Node[]>([]);
  const animRef = useRef<number>(0);

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

    const draw = () => {
      const W = canvas.width, H = canvas.height;
      ctx.clearRect(0, 0, W, H);

      const bg = ctx.createRadialGradient(W / 2, H / 2, 0, W / 2, H / 2, Math.max(W, H) * 0.8);
      bg.addColorStop(0, 'rgba(6,20,40,1)');
      bg.addColorStop(1, 'rgba(4,8,16,1)');
      ctx.fillStyle = bg;
      ctx.fillRect(0, 0, W, H);

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
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.strokeStyle = `rgba(6,182,212,${alpha})`;
            ctx.lineWidth = 0.8;
            ctx.stroke();
          }
        }
      }

      nodes.forEach(n => {
        const pulseMag = 0.5 + 0.5 * Math.sin(n.pulse);

        const grd = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, n.radius * 6);
        grd.addColorStop(0, `rgba(6,182,212,${0.15 * pulseMag})`);
        grd.addColorStop(1, 'rgba(0,0,0,0)');
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.radius * 6, 0, Math.PI * 2);
        ctx.fillStyle = grd;
        ctx.fill();

        ctx.beginPath();
        ctx.arc(n.x, n.y, n.radius * pulseMag, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(6,182,212,0.9)`;
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


// ─── Landing Page ─────────────────────────────────────────────────────────────
export default function LandingPage() {
  const router = useRouter();

  return (
    <main className={styles.main}>
      <NetworkCanvas />

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

          <div className={styles.ctaRow}>
            <button
              className={styles.ctaSecondary}
              onClick={() => router.push('/login')}
            >
              Sign in →
            </button>
            <button
              className={styles.ctaPrimary}
              onClick={() => router.push('/signup')}
            >
              Get started free →
            </button>
          </div>

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

'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { getUsername, logout } from '../../lib/auth';
import styles from './layout.module.css';

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();

  return (
    <div className={styles.shell}>
      <nav className={styles.nav}>
        <Link href="/dashboard" className={styles.brand}>
          <span className={styles.brandIcon}>⌖</span>
          AgentVAPT
        </Link>

        <div className={styles.navLinks}>
          <Link
            href="/dashboard"
            className={`${styles.navLink} ${pathname === '/dashboard' ? styles.navLinkActive : ''}`}
          >
            Start Scan
          </Link>
          <Link
            href="/dashboard/scans"
            className={`${styles.navLink} ${pathname === '/dashboard/scans' ? styles.navLinkActive : ''}`}
          >
            Scans
          </Link>
        </div>

        <div className={styles.userArea}>
          <span className={styles.username}>{getUsername()}</span>
          <button className={styles.logoutBtn} onClick={logout}>Sign out</button>
        </div>
      </nav>

      <main className={styles.content}>
        {children}
      </main>
    </div>
  );
}

export interface ExposedFile {
  path: string;
  status: number;
  contentPreview: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
}

export interface FileExposureResult {
  baseUrl: string;
  exposed: ExposedFile[];
  checked: number;
}

const DEFAULT_PATHS: { path: string; severity: "critical" | "high" | "medium" | "low"; description: string }[] = [
  // Critical - direct credential/config exposure
  { path: "/.env", severity: "critical", description: "Environment file may contain secrets and credentials" },
  { path: "/.env.local", severity: "critical", description: "Local environment file with secrets" },
  { path: "/.env.production", severity: "critical", description: "Production environment file with secrets" },
  { path: "/config.php", severity: "critical", description: "PHP config file may contain DB credentials" },
  { path: "/wp-config.php", severity: "critical", description: "WordPress config with DB credentials" },
  { path: "/database.yml", severity: "critical", description: "Database configuration file" },
  { path: "/config/database.yml", severity: "critical", description: "Rails database config" },
  { path: "/.git/config", severity: "critical", description: "Git config exposes repo info and credentials" },

  // High - admin/sensitive endpoints
  { path: "/admin", severity: "high", description: "Admin panel exposed" },
  { path: "/admin/", severity: "high", description: "Admin panel exposed" },
  { path: "/administrator", severity: "high", description: "Administrator panel exposed" },
  { path: "/phpmyadmin", severity: "high", description: "phpMyAdmin database admin exposed" },
  { path: "/phpmyadmin/", severity: "high", description: "phpMyAdmin database admin exposed" },
  { path: "/wp-admin/", severity: "high", description: "WordPress admin exposed" },
  { path: "/backup", severity: "high", description: "Backup directory exposed" },
  { path: "/backup.sql", severity: "high", description: "SQL backup file exposed" },
  { path: "/backup.zip", severity: "high", description: "Backup archive exposed" },
  { path: "/db.sql", severity: "high", description: "Database dump exposed" },
  { path: "/dump.sql", severity: "high", description: "Database dump exposed" },

  // Medium - info disclosure
  { path: "/server-status", severity: "medium", description: "Apache server-status page exposed" },
  { path: "/server-info", severity: "medium", description: "Apache server-info page exposed" },
  { path: "/.htaccess", severity: "medium", description: "Apache htaccess file exposed" },
  { path: "/web.config", severity: "medium", description: "IIS web config exposed" },
  { path: "/package.json", severity: "medium", description: "Node.js package.json exposes dependencies" },
  { path: "/composer.json", severity: "medium", description: "PHP composer.json exposes dependencies" },
  { path: "/README.md", severity: "low", description: "README file exposed" },
  { path: "/.gitignore", severity: "low", description: ".gitignore reveals file structure" },
  { path: "/robots.txt", severity: "low", description: "robots.txt may reveal hidden paths" },
  { path: "/sitemap.xml", severity: "low", description: "Sitemap reveals all paths" },
  { path: "/.DS_Store", severity: "medium", description: ".DS_Store reveals Mac filesystem structure" },
];

export async function testFileExposure(
  baseUrl: string,
  customPaths?: string[]
): Promise<FileExposureResult> {
  const baseOrigin = new URL(baseUrl).origin;
  const pathsToCheck = customPaths
    ? customPaths.map((p) => ({ path: p, severity: "medium" as const, description: "Custom path" }))
    : DEFAULT_PATHS;

  const exposed: ExposedFile[] = [];

  // Check in parallel batches of 10
  const batchSize = 10;
  for (let i = 0; i < pathsToCheck.length; i += batchSize) {
    const batch = pathsToCheck.slice(i, i + batchSize);
    const results = await Promise.all(
      batch.map(async ({ path, severity, description }) => {
        const url = `${baseOrigin}${path}`;
        try {
          const controller = new AbortController();
          setTimeout(() => controller.abort(), 5000);
          const res = await fetch(url, {
            signal: controller.signal,
            headers: { "User-Agent": "AgenticVAPT/1.0 Security Scanner" },
            redirect: "follow",
          });

          // Only flag as exposed if we get a 200 OK (or 301/302 to same origin)
          if (res.status === 200) {
            const text = await res.text();
            const preview = text.slice(0, 300).replace(/\n/g, " ");
            return {
              path,
              status: res.status,
              contentPreview: preview,
              severity,
              description,
            } as ExposedFile;
          }
          return null;
        } catch {
          return null;
        }
      })
    );

    for (const result of results) {
      if (result) exposed.push(result);
    }
  }

  return { baseUrl, exposed, checked: pathsToCheck.length };
}

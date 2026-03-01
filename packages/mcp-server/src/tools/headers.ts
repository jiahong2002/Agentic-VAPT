export interface HeaderFinding {
  header: string;
  issue: string;
  severity: "high" | "medium" | "low";
  recommendation: string;
}

export interface HeadersResult {
  url: string;
  grade: "A" | "B" | "C" | "D" | "F";
  presentHeaders: Record<string, string>;
  missingHeaders: string[];
  findings: HeaderFinding[];
}

const SECURITY_HEADERS: Record<string, { severity: "high" | "medium" | "low"; recommendation: string }> = {
  "strict-transport-security": {
    severity: "high",
    recommendation: "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
  },
  "content-security-policy": {
    severity: "high",
    recommendation: "Add a Content-Security-Policy header to prevent XSS and data injection attacks",
  },
  "x-content-type-options": {
    severity: "medium",
    recommendation: "Add: X-Content-Type-Options: nosniff",
  },
  "x-frame-options": {
    severity: "medium",
    recommendation: "Add: X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking",
  },
  "x-xss-protection": {
    severity: "low",
    recommendation: "Add: X-XSS-Protection: 1; mode=block (legacy browsers)",
  },
  "referrer-policy": {
    severity: "low",
    recommendation: "Add: Referrer-Policy: strict-origin-when-cross-origin",
  },
  "permissions-policy": {
    severity: "low",
    recommendation: "Add a Permissions-Policy header to restrict browser features",
  },
};

function gradeFromFindings(findings: HeaderFinding[]): "A" | "B" | "C" | "D" | "F" {
  const highCount = findings.filter((f) => f.severity === "high").length;
  const mediumCount = findings.filter((f) => f.severity === "medium").length;
  if (highCount >= 2) return "F";
  if (highCount === 1) return "D";
  if (mediumCount >= 2) return "C";
  if (mediumCount === 1) return "B";
  return "A";
}

export async function testSecurityHeaders(url: string): Promise<HeadersResult> {
  let responseHeaders: Record<string, string> = {};

  try {
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 8000);
    const res = await fetch(url, {
      method: "HEAD",
      signal: controller.signal,
      headers: { "User-Agent": "AgenticVAPT/1.0 Security Scanner" },
      redirect: "follow",
    });
    res.headers.forEach((value, key) => {
      responseHeaders[key.toLowerCase()] = value;
    });
  } catch {
    // fallback to GET if HEAD fails
    try {
      const res = await fetch(url, {
        headers: { "User-Agent": "AgenticVAPT/1.0 Security Scanner" },
        redirect: "follow",
      });
      res.headers.forEach((value, key) => {
        responseHeaders[key.toLowerCase()] = value;
      });
    } catch {
      responseHeaders = {};
    }
  }

  const findings: HeaderFinding[] = [];
  const missingHeaders: string[] = [];

  for (const [header, config] of Object.entries(SECURITY_HEADERS)) {
    if (!responseHeaders[header]) {
      missingHeaders.push(header);
      findings.push({
        header,
        issue: `Missing security header: ${header}`,
        severity: config.severity,
        recommendation: config.recommendation,
      });
    }
  }

  // Check for server info disclosure
  if (responseHeaders["server"]) {
    findings.push({
      header: "server",
      issue: `Server header discloses technology: ${responseHeaders["server"]}`,
      severity: "low",
      recommendation: "Remove or genericize the Server header to avoid fingerprinting",
    });
  }

  // Check for X-Powered-By disclosure
  if (responseHeaders["x-powered-by"]) {
    findings.push({
      header: "x-powered-by",
      issue: `X-Powered-By discloses technology: ${responseHeaders["x-powered-by"]}`,
      severity: "low",
      recommendation: "Remove the X-Powered-By header",
    });
  }

  return {
    url,
    grade: gradeFromFindings(findings),
    presentHeaders: responseHeaders,
    missingHeaders,
    findings,
  };
}

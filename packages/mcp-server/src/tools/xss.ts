export interface XSSResult {
  url: string;
  paramName: string;
  vulnerable: boolean;
  type: "reflected" | "stored" | null;
  payload: string | null;
  evidence: string | null;
  severity: "high" | "medium" | "low";
}

// Unique markers embedded in payloads so we can detect reflection
const MARKER = "VAPT_XSS_7x9k";

const XSS_PAYLOADS = [
  `<script>alert("${MARKER}")</script>`,
  `"><script>alert("${MARKER}")</script>`,
  `'><script>alert("${MARKER}")</script>`,
  `<img src=x onerror="alert('${MARKER}')">`,
  `"><img src=x onerror="alert('${MARKER}')">`,
  `javascript:alert("${MARKER}")`,
  `<svg onload="alert('${MARKER}')">`,
  `<body onload="alert('${MARKER}')">`,
];

async function makeRequest(
  url: string,
  method: string,
  paramName: string,
  paramValue: string
): Promise<string | null> {
  try {
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 8000);

    let res: Response;
    if (method === "GET") {
      const qs = new URLSearchParams({ [paramName]: paramValue }).toString();
      res = await fetch(`${url}?${qs}`, {
        signal: controller.signal,
        headers: { "User-Agent": "AgenticVAPT/1.0 Security Scanner" },
        redirect: "follow",
      });
    } else {
      res = await fetch(url, {
        method: "POST",
        signal: controller.signal,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "User-Agent": "AgenticVAPT/1.0 Security Scanner",
        },
        body: new URLSearchParams({ [paramName]: paramValue }).toString(),
        redirect: "follow",
      });
    }

    return await res.text();
  } catch {
    return null;
  }
}

function isPayloadReflectedUnescaped(body: string, payload: string): boolean {
  // Check if the full payload or key parts appear unescaped in the response
  if (body.includes(payload)) return true;

  // Check for partial reflection of dangerous patterns
  const dangerousPatterns = [
    `<script>alert("${MARKER}")`,
    `onerror="alert('${MARKER}')"`,
    `onload="alert('${MARKER}')"`,
    MARKER,
  ];

  return dangerousPatterns.some((p) => body.includes(p));
}

export async function testXSS(params: {
  url: string;
  method: string;
  paramName: string;
  payloads?: string[];
}): Promise<XSSResult> {
  const { url, method, paramName, payloads = XSS_PAYLOADS } = params;

  for (const payload of payloads) {
    const body = await makeRequest(url, method, paramName, payload);
    if (!body) continue;

    if (isPayloadReflectedUnescaped(body, payload)) {
      // Extract context around the reflection
      const markerIdx = body.indexOf(MARKER);
      const contextStart = Math.max(0, markerIdx - 80);
      const contextEnd = Math.min(body.length, markerIdx + 80);
      const context = body.slice(contextStart, contextEnd).replace(/\n/g, " ");

      return {
        url,
        paramName,
        vulnerable: true,
        type: "reflected",
        payload,
        evidence: `Payload reflected unescaped in response at: ...${context}...`,
        severity: "high",
      };
    }
  }

  return { url, paramName, vulnerable: false, type: null, payload: null, evidence: null, severity: "low" };
}

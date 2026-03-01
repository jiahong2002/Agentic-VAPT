import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { crawlSite } from "./tools/crawler.js";
import { testSecurityHeaders } from "./tools/headers.js";
import { testFileExposure } from "./tools/fileExposure.js";
import { testSQLi } from "./tools/sqli.js";
import { testXSS } from "./tools/xss.js";

const server = new McpServer({
  name: "vapt-tools",
  version: "1.0.0",
});

// ── Tool 1: Crawl site ──────────────────────────────────────────────────────
server.tool(
  "crawl_site",
  "Crawls a target URL and returns all discovered pages, forms, input fields, and links.",
  {
    url: z.string().url().describe("The base URL to crawl"),
    max_depth: z.number().int().min(1).max(5).default(2).describe("Maximum crawl depth (default 2)"),
    max_pages: z.number().int().min(1).max(100).default(30).describe("Maximum pages to visit (default 30)"),
  },
  async ({ url, max_depth, max_pages }) => {
    const result = await crawlSite(url, max_depth, max_pages);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ── Tool 2: Test security headers ───────────────────────────────────────────
server.tool(
  "test_security_headers",
  "Fetches HTTP headers for a URL and evaluates missing or misconfigured security headers.",
  {
    url: z.string().url().describe("The URL to check headers on"),
  },
  async ({ url }) => {
    const result = await testSecurityHeaders(url);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ── Tool 3: Test file exposure ───────────────────────────────────────────────
server.tool(
  "test_file_exposure",
  "Probes a target host for commonly exposed sensitive files, backup files, and admin endpoints.",
  {
    base_url: z.string().url().describe("The base URL of the target"),
    paths: z
      .array(z.string())
      .optional()
      .describe("Custom paths to probe. Uses built-in wordlist if omitted."),
  },
  async ({ base_url, paths }) => {
    const result = await testFileExposure(base_url, paths);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ── Tool 4: Test SQL injection ───────────────────────────────────────────────
server.tool(
  "test_sqli",
  "Tests a form endpoint for SQL injection vulnerabilities using error-based, boolean-based, and time-based techniques.",
  {
    url: z.string().url().describe("The form action URL to test"),
    method: z.enum(["GET", "POST"]).describe("HTTP method of the form"),
    param_name: z.string().describe("The input parameter name to inject into"),
    baseline_value: z
      .string()
      .default("1")
      .describe("A normal value for the parameter to establish baseline"),
    payloads: z.array(z.string()).optional().describe("Custom payloads (uses built-in list if omitted)"),
  },
  async ({ url, method, param_name, baseline_value, payloads }) => {
    const result = await testSQLi({ url, method, paramName: param_name, baselineValue: baseline_value, payloads });
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ── Tool 5: Test XSS ─────────────────────────────────────────────────────────
server.tool(
  "test_xss",
  "Tests a URL parameter or form field for reflected XSS vulnerabilities by checking if payloads are reflected unescaped.",
  {
    url: z.string().url().describe("Target URL"),
    method: z.enum(["GET", "POST"]).describe("HTTP method"),
    param_name: z.string().describe("Parameter name to inject XSS payload into"),
    payloads: z.array(z.string()).optional().describe("Custom XSS payloads (uses built-in list if omitted)"),
  },
  async ({ url, method, param_name, payloads }) => {
    const result = await testXSS({ url, method, paramName: param_name, payloads });
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ── Start server ─────────────────────────────────────────────────────────────
const transport = new StdioServerTransport();
await server.connect(transport);

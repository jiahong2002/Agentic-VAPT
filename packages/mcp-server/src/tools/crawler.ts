import * as cheerio from "cheerio";

export interface FormInput {
  name: string;
  type: string;
  value?: string;
}

export interface PageForm {
  action: string;
  method: string;
  inputs: FormInput[];
}

export interface CrawledPage {
  url: string;
  title: string;
  forms: PageForm[];
  links: string[];
  statusCode: number;
}

export interface CrawlResult {
  baseUrl: string;
  pages: CrawledPage[];
  totalPages: number;
  allForms: (PageForm & { pageUrl: string })[];
  allLinks: string[];
}

function normalizeUrl(href: string, base: string): string | null {
  try {
    const url = new URL(href, base);
    // Only follow same-origin links
    const baseOrigin = new URL(base).origin;
    if (url.origin !== baseOrigin) return null;
    // Strip fragments
    url.hash = "";
    return url.toString();
  } catch {
    return null;
  }
}

async function fetchPage(url: string, timeoutMs = 8000): Promise<{ html: string; status: number } | null> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { "User-Agent": "AgenticVAPT/1.0 Security Scanner" },
      redirect: "follow",
    });
    clearTimeout(timer);
    const html = await res.text();
    return { html, status: res.status };
  } catch {
    return null;
  }
}

export async function crawlSite(
  baseUrl: string,
  maxDepth = 2,
  maxPages = 30
): Promise<CrawlResult> {
  const visited = new Set<string>();
  const queue: { url: string; depth: number }[] = [{ url: baseUrl, depth: 0 }];
  const pages: CrawledPage[] = [];

  while (queue.length > 0 && pages.length < maxPages) {
    const item = queue.shift();
    if (!item) break;
    const { url, depth } = item;

    if (visited.has(url)) continue;
    visited.add(url);

    const fetched = await fetchPage(url);
    if (!fetched) continue;

    const $ = cheerio.load(fetched.html);
    const title = $("title").text().trim() || url;
    const links: string[] = [];
    const forms: PageForm[] = [];

    // Collect links
    $("a[href]").each((_, el) => {
      const href = $(el).attr("href");
      if (!href) return;
      const normalized = normalizeUrl(href, url);
      if (normalized && !visited.has(normalized)) {
        links.push(normalized);
        if (depth < maxDepth) {
          queue.push({ url: normalized, depth: depth + 1 });
        }
      }
    });

    // Collect forms
    $("form").each((_, formEl) => {
      const action = $(formEl).attr("action") || url;
      const method = ($(formEl).attr("method") || "GET").toUpperCase();
      const normalizedAction = normalizeUrl(action, url) || action;
      const inputs: FormInput[] = [];

      $(formEl)
        .find("input, textarea, select")
        .each((_, inputEl) => {
          const name = $(inputEl).attr("name");
          if (name) {
            inputs.push({
              name,
              type: $(inputEl).attr("type") || $(inputEl).prop("tagName")?.toLowerCase() || "text",
              value: $(inputEl).attr("value"),
            });
          }
        });

      if (inputs.length > 0) {
        forms.push({ action: normalizedAction, method, inputs });
      }
    });

    pages.push({ url, title, forms, links: [...new Set(links)], statusCode: fetched.status });
  }

  const allForms = pages.flatMap((p) =>
    p.forms.map((f) => ({ ...f, pageUrl: p.url }))
  );
  const allLinks = [...new Set(pages.flatMap((p) => p.links))];

  return { baseUrl, pages, totalPages: pages.length, allForms, allLinks };
}

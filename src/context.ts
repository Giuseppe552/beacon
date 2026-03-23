import type { ScanContext } from "./types.js";

/**
 * Build scan context: fetch the target, collect HTML and headers.
 * Tries HTTPS first, checks if HTTP redirects to HTTPS.
 */
export async function buildContext(domain: string): Promise<ScanContext> {
  const url = `https://${domain}`;
  let httpsRedirect = false;

  // Check if HTTP redirects to HTTPS
  try {
    const httpRes = await fetch(`http://${domain}`, {
      method: "HEAD",
      redirect: "manual",
      signal: AbortSignal.timeout(8000),
    });
    const location = httpRes.headers.get("location") ?? "";
    httpsRedirect =
      httpRes.status >= 300 &&
      httpRes.status < 400 &&
      location.startsWith("https://");
  } catch {
    // HTTP not reachable or timeout — that's fine
  }

  const res = await fetch(url, {
    redirect: "follow",
    signal: AbortSignal.timeout(15000),
    headers: {
      "User-Agent":
        "Mozilla/5.0 (compatible; beacon-scanner/0.1; +https://giuseppegiona.com/projects/beacon)",
      Accept: "text/html,application/xhtml+xml",
    },
  });

  const html = await res.text();
  const headers: Record<string, string> = {};
  res.headers.forEach((v, k) => {
    headers[k.toLowerCase()] = v;
  });

  return {
    domain,
    url,
    html,
    headers,
    statusCode: res.status,
    httpsRedirect,
  };
}

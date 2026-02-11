const SECRET_KEY = Deno.env.get("SECRET_KEY") || "change-this-key-1234";
const ADMIN_PATH = Deno.env.get("ADMIN_PATH") || "mySecret-panel-7x9k";
const ADMIN_PASSWORD = Deno.env.get("ADMIN_PASSWORD") || "change-admin-pass-5678";
const MIME_TYPES: Record<string, string> = {
  ".mp4": "video/mp4",
  ".mkv": "video/x-matroska",
  ".webm": "video/webm",
  ".avi": "video/x-msvideo",
  ".mov": "video/quicktime",
  ".ts": "video/mp2t",
  ".m3u8": "application/x-mpegURL",
  ".flv": "video/x-flv",
  ".wmv": "video/x-ms-wmv",
  ".3gp": "video/3gpp",
};
const ALLOWED_EXTENSIONS = new Set(Object.keys(MIME_TYPES));
function getMimeType(filename: string): string {
  const ext = filename.substring(filename.lastIndexOf(".")).toLowerCase();
  return MIME_TYPES[ext] || "application/octet-stream";
}
function getExtension(filename: string): string {
  const dot = filename.lastIndexOf(".");
  return dot !== -1 ? filename.substring(dot).toLowerCase() : "";
}
function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
let cachedKey: CryptoKey | null = null;
async function getHmacKey(): Promise<CryptoKey> {
  if (!cachedKey) {
    cachedKey = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(SECRET_KEY),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
  }
  return cachedKey;
}
function uint8ToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\
    .replace(/=+$/, "");
}
async function hmacSign(data: string): Promise<string> {
  const key = await getHmacKey();
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(data)
  );
  return uint8ToBase64Url(new Uint8Array(sig));
}
async function hmacVerify(data: string, signature: string): Promise<boolean> {
  const expected = await hmacSign(data);
  if (expected.length !== signature.length) return false;
  const a = new TextEncoder().encode(expected);
  const b = new TextEncoder().encode(signature);
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) {
    mismatch |= a[i] ^ b[i];
  }
  return mismatch === 0;
}
function encodeURL(url: string): string {
  const bytes = new TextEncoder().encode(url);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\
    .replace(/=+$/, "");
}
function decodeURL(encoded: string): string {
  let b64 = encoded.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  const binary = atob(b64);
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}
function isValidVideoUrl(str: string): boolean {
  try {
    const u = new URL(str);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}
function isSafeUrl(urlStr: string): boolean {
  try {
    const u = new URL(urlStr);
    const hostname = u.hostname.toLowerCase();
    if (
      hostname === "localhost" ||
      hostname === "127.0.0.1" ||
      hostname === "0.0.0.0" ||
      hostname === "[::1]" ||
      hostname.startsWith("10.") ||
      hostname.startsWith("192.168.") ||
      hostname.startsWith("169.254.") ||
      hostname.endsWith(".local") ||
      hostname.endsWith(".internal") ||
      hostname.endsWith(".localhost")
    ) {
      return false;
    }
    if (hostname.startsWith("172.")) {
      const second = parseInt(hostname.split(".")[1], 10);
      if (second >= 16 && second <= 31) return false;
    }
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}
function extractFilename(videoUrl: string, rawFilename: string): string {
  let filename = rawFilename.trim();
  if (!filename) {
    try {
      const p = new URL(videoUrl).pathname.split("/").pop() || "video.mp4";
      filename = p.includes(".") ? decodeURIComponent(p) : "video.mp4";
    } catch {
      filename = "video.mp4";
    }
  }
  const ext = getExtension(filename);
  if (!ext || !ALLOWED_EXTENSIONS.has(ext)) {
    const baseName = filename.replace(/\.[^.]+$/, "") || "video";
    filename = baseName + ".mp4";
  }
  filename = filename.replace(/[^\w\-.() ]/g, "_");
  return filename;
}
const rateLimitMap = new Map<string, { count: number; resetAt: number }>();
function isRateLimited(
  ip: string,
  maxRequests = 60,
  windowMs = 60_000
): boolean {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);
  if (!entry || now > entry.resetAt) {
    rateLimitMap.set(ip, { count: 1, resetAt: now + windowMs });
    return false;
  }
  entry.count++;
  return entry.count > maxRequests;
}
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of rateLimitMap) {
    if (now > entry.resetAt) rateLimitMap.delete(ip);
  }
}, 5 * 60_000); 
function getClientIp(req: Request): string {
  return (
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    req.headers.get("cf-connecting-ip") ||
    req.headers.get("x-real-ip") ||
    "unknown"
  );
}
const SESSION_COOKIE = "admin_session";
const SESSION_MAX_AGE = 60 * 60 * 8; 
async function createSessionToken(): Promise<string> {
  const payload = `session:${Date.now()}`;
  const sig = await hmacSign(payload);
  const token = encodeURL(payload) + "." + sig;
  return token;
}
async function verifySessionToken(token: string): Promise<boolean> {
  try {
    const [encodedPayload, sig] = token.split(".");
    if (!encodedPayload || !sig) return false;
    const payload = decodeURL(encodedPayload);
    if (!payload.startsWith("session:")) return false;
    const valid = await hmacVerify(encodedPayload, sig);
    if (!valid) return false;
    const timestamp = parseInt(payload.split(":")[1], 10);
    if (Date.now() - timestamp > SESSION_MAX_AGE * 1000) return false;
    return true;
  } catch {
    return false;
  }
}
function getSessionFromCookie(req: Request): string | null {
  const cookie = req.headers.get("cookie") || "";
  const match = cookie.match(new RegExp(`${SESSION_COOKIE}=([^;]+)`));
  return match ? match[1] : null;
}
async function isAdminAuthenticated(req: Request): Promise<boolean> {
  const token = getSessionFromCookie(req);
  if (!token) return false;
  return await verifySessionToken(token);
}
function loginPage(error?: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Login</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: 'Segoe UI', sans-serif;
      background: #0f0f23;
      color: #e0e0e0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .container {
      background: #1a1a2e;
      padding: 40px;
      border-radius: 16px;
      width: 90%;
      max-width: 400px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.5);
    }
    h1 {
      text-align: center;
      margin-bottom: 24px;
      background: linear-gradient(135deg, #667eea, #764ba2);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    label { display: block; margin-bottom: 8px; font-weight: 600; }
    input {
      width: 100%;
      padding: 12px 16px;
      border: 1px solid #333;
      border-radius: 8px;
      background: #16213e;
      color: #fff;
      font-size: 14px;
      margin-bottom: 20px;
    }
    input:focus { outline: none; border-color: #667eea; }
    .btn {
      width: 100%;
      padding: 14px;
      background: linear-gradient(135deg, #667eea, #764ba2);
      color: #fff;
      border: none;
      border-radius: 8px;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: transform 0.2s;
    }
    .btn:hover { transform: translateY(-2px); }
    .error {
      margin-bottom: 16px;
      padding: 12px;
      background: #2e1a1a;
      border: 1px solid #ff6b6b;
      border-radius: 8px;
      color: #ff6b6b;
      text-align: center;
      font-size: 14px;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>Admin Login</h1>
    ${error ? `<div class="error">${escapeHtml(error)}</div>` : ""}
    <form method="POST">
      <label>Password</label>
      <input type="password" name="password" required placeholder="Enter admin password" autofocus>
      <button type="submit" class="btn">Login</button>
    </form>
  </div>
</body>
</html>`;
}
function adminPage(
  baseUrl: string,
  result?: { link?: string; error?: string }
): string {
  const safeLink = result?.link ? escapeHtml(result.link) : "";
  const safeError = result?.error ? escapeHtml(result.error) : "";
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Link Generator</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: 'Segoe UI', sans-serif;
      background: #0f0f23;
      color: #e0e0e0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .container {
      background: #1a1a2e;
      padding: 40px;
      border-radius: 16px;
      width: 90%;
      max-width: 650px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.5);
    }
    h1 {
      text-align: center;
      margin-bottom: 8px;
      background: linear-gradient(135deg, #667eea, #764ba2);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .subtitle {
      text-align: center;
      color: #888;
      font-size: 13px;
      margin-bottom: 30px;
    }
    .topbar {
      display: flex;
      justify-content: flex-end;
      margin-bottom: 16px;
    }
    .logout-btn {
      padding: 6px 16px;
      background: #333;
      color: #ccc;
      border: none;
      border-radius: 6px;
      cursor: pointer;
      font-size: 13px;
    }
    .logout-btn:hover { background: #555; }
    label { display: block; margin-bottom: 8px; font-weight: 600; }
    input, select {
      width: 100%;
      padding: 12px 16px;
      border: 1px solid #333;
      border-radius: 8px;
      background: #16213e;
      color: #fff;
      font-size: 14px;
      margin-bottom: 20px;
    }
    input:focus, select:focus { outline: none; border-color: #667eea; }
    .btn {
      width: 100%;
      padding: 14px;
      background: linear-gradient(135deg, #667eea, #764ba2);
      color: #fff;
      border: none;
      border-radius: 8px;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: transform 0.2s;
    }
    .btn:hover { transform: translateY(-2px); }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }
    .result {
      margin-top: 20px;
      padding: 16px;
      background: #16213e;
      border-radius: 8px;
      word-break: break-all;
      border: 1px solid #667eea;
    }
    .result a { color: #667eea; text-decoration: none; }
    .copy-btn {
      margin-top: 10px;
      padding: 8px 16px;
      font-size: 13px;
      background: #333;
      color: #fff;
      border: none;
      border-radius: 6px;
      cursor: pointer;
    }
    .copy-btn:hover { background: #555; }
    .error {
      margin-top: 20px;
      padding: 16px;
      background: #2e1a1a;
      border: 1px solid #ff6b6b;
      border-radius: 8px;
      color: #ff6b6b;
    }
    .batch-area {
      width: 100%;
      min-height: 120px;
      padding: 12px 16px;
      border: 1px solid #333;
      border-radius: 8px;
      background: #16213e;
      color: #fff;
      font-size: 13px;
      margin-bottom: 20px;
      resize: vertical;
      font-family: monospace;
    }
    .tabs { display: flex; gap: 8px; margin-bottom: 24px; }
    .tab {
      flex: 1;
      padding: 10px;
      text-align: center;
      background: #16213e;
      border: 1px solid #333;
      border-radius: 8px;
      cursor: pointer;
      font-weight: 600;
      transition: all 0.2s;
    }
    .tab.active { background: #667eea; border-color: #667eea; }
    .panel { display: none; }
    .panel.active { display: block; }
  </style>
</head>
<body>
  <div class="container">
    <div class="topbar">
      <form method="POST" action="/${ADMIN_PATH}/logout">
        <button type="submit" class="logout-btn">Logout</button>
      </form>
    </div>
    <h1>Proxy Link Generator</h1>
    <p class="subtitle">Generate proxy streaming links for your app.</p>
    <div class="tabs">
      <div class="tab active" onclick="switchTab('single')">Single Link</div>
      <div class="tab" onclick="switchTab('batch')">Batch Links</div>
    </div>
    <!-- Single Link -->
    <div id="single" class="panel active">
      <form method="POST">
        <label>Direct Video URL</label>
        <input type="url" name="url" required placeholder="https://example.com/movie.mp4" id="urlInput">
        <label>Filename (optional)</label>
        <input type="text" name="filename" placeholder="My-Movie.mp4" id="fnInput">
        <button type="submit" class="btn">Generate Proxy Link</button>
      </form>
    </div>
    <!-- Batch Links -->
    <div id="batch" class="panel">
      <label>Paste URLs (one per line)</label>
      <textarea class="batch-area" id="batchUrls" placeholder="https://example.com/movie1.mp4&#10;https://example.com/movie2.mp4&#10;https://example.com/movie3.mp4"></textarea>
      <button class="btn" onclick="batchGenerate()">Generate All</button>
      <div id="batchResults"></div>
    </div>
    ${
      safeLink
        ? `
    <div class="result">
      <strong>Proxy Link:</strong><br><br>
      <a href="${safeLink}" id="genLink">${safeLink}</a>
      <br>
      <button class="copy-btn" onclick="copyLink()">Copy Link</button>
      <span id="copyMsg" style="color:#4ade80;font-size:12px;margin-left:8px;display:none;">Copied!</span>
    </div>`
        : ""
    }
    ${safeError ? `<div class="error">${safeError}</div>` : ""}
  </div>
  <script>
    function switchTab(name) {
      document.querySelectorAll('.tab').forEach((t, i) => {
        t.classList.toggle('active', (name === 'single' ? i === 0 : i === 1));
      });
      document.querySelectorAll('.panel').forEach(p => {
        p.classList.toggle('active', p.id === name);
      });
    }
    function copyLink() {
      const link = document.getElementById('genLink')?.textContent;
      if (link) {
        navigator.clipboard.writeText(link);
        const msg = document.getElementById('copyMsg');
        msg.style.display = 'inline';
        setTimeout(() => msg.style.display = 'none', 2000);
      }
    }
    async function batchGenerate() {
      const text = document.getElementById('batchUrls').value.trim();
      if (!text) return;
      const urls = text.split('\\n').map(u => u.trim()).filter(u => u);
      const container = document.getElementById('batchResults');
      container.innerHTML = '<p style="margin-top:16px;color:#888;">Generating...</p>';
      const results = [];
      for (const url of urls) {
        try {
          const resp = await fetch('/${ADMIN_PATH}/api/generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
          });
          const data = await resp.json();
          results.push({ url, link: data.link, error: data.error });
        } catch (e) {
          results.push({ url, error: e.message });
        }
      }
      let html = '<div style="margin-top:16px;">';
      results.forEach((r, i) => {
        if (r.link) {
          const safeUrl = encodeURI(r.link);
          html += '<div class="result" style="margin-bottom:8px;font-size:13px;">'
            + '<b>#' + (i+1) + '</b><br>'
            + '<a href="' + safeUrl + '">' + safeUrl + '</a>'
            + ' <button class="copy-btn" style="margin-top:4px;" data-url="' + safeUrl + '" onclick="navigator.clipboard.writeText(this.dataset.url)">Copy</button>'
            + '</div>';
        } else {
          html += '<div class="error" style="margin-bottom:8px;font-size:13px;">'
            + '<b>#' + (i+1) + '</b> ' + (r.error || 'Failed') + '</div>';
        }
      });
      html += '</div>';
      container.innerHTML = html;
    }
  </script>
</body>
</html>`;
}
function errorPage(msg: string, status: number): Response {
  return new Response(
    `<!DOCTYPE html><html><head><title>Error</title>
    <style>body{background:#0f0f23;color:#ff6b6b;display:flex;align-items:center;
    justify-content:center;min-height:100vh;font-family:sans-serif;font-size:24px;}
    </style></head><body>${escapeHtml(msg)}</body></html>`,
    { status, headers: { "Content-Type": "text/html; charset=utf-8" } }
  );
}
async function fetchWithRetry(
  url: string,
  options: RequestInit,
  retries = 3,
  timeoutMs = 30_000
): Promise<Response> {
  let lastError: Error | null = null;
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      const resp = await fetch(url, {
        ...options,
        signal: controller.signal,
      });
      clearTimeout(timer);
      return resp;
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
      if (attempt === retries) break;
      await new Promise((r) => setTimeout(r, 500 * Math.pow(2, attempt - 1)));
    }
  }
  throw lastError || new Error("Fetch failed after retries");
}
Deno.serve(async (req: Request) => {
  const url = new URL(req.url);
  const path = url.pathname;
  const clientIp = getClientIp(req);
  if (isRateLimited(clientIp, 120, 60_000)) {
    return new Response(
      JSON.stringify({ error: "Too many requests. Please slow down." }),
      {
        status: 429,
        headers: {
          "Content-Type": "application/json",
          "Retry-After": "60",
        },
      }
    );
  }
  if (req.method === "OPTIONS") {
    return new Response(null, {
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Range, Authorization, Content-Type",
        "Access-Control-Max-Age": "86400",
      },
    });
  }
  if (path === `/${ADMIN_PATH}` && req.method === "GET") {
    if (await isAdminAuthenticated(req)) {
      return new Response(adminPage(url.origin), {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }
    return new Response(loginPage(), {
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }
  if (path === `/${ADMIN_PATH}` && req.method === "POST") {
    if (await isAdminAuthenticated(req)) {
      const form = await req.formData();
      const videoUrl = (form.get("url") as string || "").trim();
      const rawFilename = (form.get("filename") as string || "").trim();
      if (!videoUrl || !isValidVideoUrl(videoUrl)) {
        return new Response(
          adminPage(url.origin, { error: "Please enter a valid URL." }),
          { headers: { "Content-Type": "text/html; charset=utf-8" } }
        );
      }
      if (!isSafeUrl(videoUrl)) {
        return new Response(
          adminPage(url.origin, {
            error: "This URL is not allowed (internal/private network).",
          }),
          { headers: { "Content-Type": "text/html; charset=utf-8" } }
        );
      }
      const filename = extractFilename(videoUrl, rawFilename);
      const encoded = encodeURL(videoUrl);
      const sig = await hmacSign(encoded);
      const proxyLink = `${url.origin}/v/${encoded}/${sig}/${encodeURIComponent(filename)}`;
      return new Response(adminPage(url.origin, { link: proxyLink }), {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }
    const form = await req.formData();
    const password = (form.get("password") as string || "").trim();
    if (isRateLimited(`login:${clientIp}`, 10, 60_000)) {
      return new Response(
        loginPage("Too many login attempts. Please wait."),
        { headers: { "Content-Type": "text/html; charset=utf-8" } }
      );
    }
    if (password !== ADMIN_PASSWORD) {
      return new Response(loginPage("Invalid password."), {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }
    const sessionToken = await createSessionToken();
    return new Response(adminPage(url.origin), {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Set-Cookie": `${SESSION_COOKIE}=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_MAX_AGE}`,
      },
    });
  }
  if (path === `/${ADMIN_PATH}/logout` && req.method === "POST") {
    return new Response(loginPage(), {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Set-Cookie": `${SESSION_COOKIE}=deleted; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`,
      },
    });
  }
  if (path === `/${ADMIN_PATH}/api/generate` && req.method === "POST") {
    if (!(await isAdminAuthenticated(req))) {
      return Response.json({ error: "Unauthorized" }, { status: 401 });
    }
    try {
      const body = await req.json();
      const videoUrl = (body.url || "").trim();
      const rawFilename = (body.filename || "").trim();
      if (!videoUrl || !isValidVideoUrl(videoUrl)) {
        return Response.json({ error: "Invalid URL" }, { status: 400 });
      }
      if (!isSafeUrl(videoUrl)) {
        return Response.json(
          { error: "URL not allowed (internal network)" },
          { status: 400 }
        );
      }
      const filename = extractFilename(videoUrl, rawFilename);
      const encoded = encodeURL(videoUrl);
      const sig = await hmacSign(encoded);
      const proxyLink = `${url.origin}/v/${encoded}/${sig}/${encodeURIComponent(filename)}`;
      return Response.json({ link: proxyLink });
    } catch {
      return Response.json({ error: "Invalid request" }, { status: 400 });
    }
  }
  if (path === "/api/generate" && req.method === "POST") {
    try {
      const authHeader = req.headers.get("Authorization") || "";
      const token = authHeader.startsWith("Bearer ")
        ? authHeader.slice(7).trim()
        : "";
      if (token !== SECRET_KEY) {
        return Response.json({ error: "Unauthorized" }, { status: 403 });
      }
      const body = await req.json();
      const videoUrl = (body.url || "").trim();
      const rawFilename = (body.filename || "").trim();
      if (!videoUrl || !isValidVideoUrl(videoUrl)) {
        return Response.json({ error: "Invalid URL" }, { status: 400 });
      }
      if (!isSafeUrl(videoUrl)) {
        return Response.json(
          { error: "URL not allowed (internal network)" },
          { status: 400 }
        );
      }
      const filename = extractFilename(videoUrl, rawFilename);
      const encoded = encodeURL(videoUrl);
      const sig = await hmacSign(encoded);
      const proxyLink = `${url.origin}/v/${encoded}/${sig}/${encodeURIComponent(filename)}`;
      return Response.json({ link: proxyLink });
    } catch {
      return Response.json({ error: "Invalid request" }, { status: 400 });
    }
  }
  const streamMatch = path.match(
    /^\/v\/([A-Za-z0-9_-]+)\/([A-Za-z0-9_-]+)\/(.+)$/
  );
  if (streamMatch) {
    const [, encoded, sig, rawFilename] = streamMatch;
    const filename = decodeURIComponent(rawFilename);
    if (!(await hmacVerify(encoded, sig))) {
      return errorPage("Invalid Link", 403);
    }
    let originalUrl: string;
    try {
      originalUrl = decodeURL(encoded);
    } catch {
      return errorPage("Bad Link", 400);
    }
    if (!isSafeUrl(originalUrl)) {
      return errorPage("Blocked URL", 403);
    }
    const fetchHeaders: Record<string, string> = {
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      Referer: new URL(originalUrl).origin + "/",
    };
    const rangeHeader = req.headers.get("Range");
    if (rangeHeader) {
      fetchHeaders["Range"] = rangeHeader;
    }
    try {
      const upstream = await fetchWithRetry(
        originalUrl,
        {
          headers: fetchHeaders,
          redirect: "follow",
        },
        3,    
        30000 
      );
      if (!upstream.ok && upstream.status !== 206) {
        await upstream.body?.cancel();
        return errorPage("Source Unavailable", 502);
      }
      const mimeType = getMimeType(filename);
      const respHeaders = new Headers();
      respHeaders.set("Content-Type", mimeType);
      respHeaders.set(
        "Content-Disposition",
        `inline; filename="${filename}"; filename*=UTF-8''${encodeURIComponent(filename)}`
      );
      const contentLength = upstream.headers.get("Content-Length");
      if (contentLength) respHeaders.set("Content-Length", contentLength);
      const contentRange = upstream.headers.get("Content-Range");
      if (contentRange) respHeaders.set("Content-Range", contentRange);
      respHeaders.set("Accept-Ranges", "bytes");
      respHeaders.set("Access-Control-Allow-Origin", "*");
      respHeaders.set("Access-Control-Allow-Headers", "Range");
      respHeaders.set(
        "Access-Control-Expose-Headers",
        "Content-Range, Content-Length, Accept-Ranges"
      );
      respHeaders.set("Cache-Control", "public, max-age=86400");
      respHeaders.set("Connection", "keep-alive");
      return new Response(upstream.body, {
        status: upstream.status,
        headers: respHeaders,
      });
    } catch (err) {
      const message =
        err instanceof Error && err.name === "AbortError"
          ? "Source Timeout"
          : "Proxy Error";
      return errorPage(message, 502);
    }
  }
  if (path === "/health") {
    return Response.json({ status: "ok", timestamp: Date.now() });
  }
  return errorPage("Not Found", 404);
});

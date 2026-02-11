const SECRET_KEY = Deno.env.get("SECRET_KEY") || "change-this-key-1234";
const ADMIN_PATH = Deno.env.get("ADMIN_PATH") || "mySecret-panel-7x9k";
// Admin URL => https://your-app.deno.dev/mySecret-panel-7x9k
// ဒီ path ကို ကိုယ့်ဟာကိုယ် ကြိုက်တာပြင်

// ========== Crypto Helpers ==========

async function hmacSign(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(SECRET_KEY),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function hmacVerify(data: string, signature: string): Promise<boolean> {
  const expected = await hmacSign(data);
  return expected === signature;
}

// ========== URL Encode/Decode ==========

function encodeURL(url: string): string {
  return btoa(unescape(encodeURIComponent(url)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function decodeURL(encoded: string): string {
  let b64 = encoded.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  return decodeURIComponent(escape(atob(b64)));
}

// ========== Admin HTML ==========

function adminPage(baseUrl: string, result?: { link?: string; error?: string }): string {
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
    <h1>Proxy Link Generator</h1>
    <p class="subtitle">No key needed. Just paste & generate.</p>

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

    ${result?.link ? `
    <div class="result">
      <strong>Proxy Link:</strong><br><br>
      <a href="${result.link}" id="genLink">${result.link}</a>
      <br>
      <button class="copy-btn" onclick="copyLink()">Copy Link</button>
      <span id="copyMsg" style="color:#4ade80;font-size:12px;margin-left:8px;display:none;">Copied!</span>
    </div>` : ""}

    ${result?.error ? `
    <div class="error">${result.error}</div>` : ""}
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
          html += '<div class="result" style="margin-bottom:8px;font-size:13px;">'
            + '<b>#' + (i+1) + '</b><br>'
            + '<a href="' + r.link + '">' + r.link + '</a>'
            + ' <button class="copy-btn" style="margin-top:4px;" onclick="navigator.clipboard.writeText(\\'' + r.link + '\\')">Copy</button>'
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
    </style></head><body>${msg}</body></html>`,
    { status, headers: { "Content-Type": "text/html; charset=utf-8" } }
  );
}

// ========== Main Handler ==========

Deno.serve(async (req: Request) => {
  const url = new URL(req.url);
  const path = url.pathname;

  // ---------- Admin Panel (GET) ----------
  if (path === `/${ADMIN_PATH}` && req.method === "GET") {
    return new Response(adminPage(url.origin), {
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }

  // ---------- Admin Generate (POST form) ----------
  if (path === `/${ADMIN_PATH}` && req.method === "POST") {
    const form = await req.formData();
    const videoUrl = (form.get("url") as string || "").trim();
    let filename = (form.get("filename") as string || "").trim();

    // URL validate
    if (!videoUrl || !videoUrl.startsWith("http")) {
      return new Response(
        adminPage(url.origin, { error: "Please enter a valid URL." }),
        { headers: { "Content-Type": "text/html; charset=utf-8" } }
      );
    }

    if (!filename) {
      try {
        const p = new URL(videoUrl).pathname.split("/").pop() || "video.mp4";
        filename = p.includes(".") ? p : "video.mp4";
      } catch {
        filename = "video.mp4";
      }
    }
    if (!filename.endsWith(".mp4")) {
      filename = filename.replace(/\.[^.]+$/, "") + ".mp4";
    }

    const encoded = encodeURL(videoUrl);
    const sig = await hmacSign(encoded);
    const proxyLink = `${url.origin}/v/${encoded}/${sig}/${encodeURIComponent(filename)}`;

    return new Response(
      adminPage(url.origin, { link: proxyLink }),
      { headers: { "Content-Type": "text/html; charset=utf-8" } }
    );
  }

  // ---------- Admin API Generate (for batch & app) ----------
  if (path === `/${ADMIN_PATH}/api/generate` && req.method === "POST") {
    try {
      const body = await req.json();
      const videoUrl = (body.url || "").trim();
      let filename = (body.filename || "").trim();

      if (!videoUrl || !videoUrl.startsWith("http")) {
        return Response.json({ error: "Invalid URL" }, { status: 400 });
      }

      if (!filename) {
        try {
          const p = new URL(videoUrl).pathname.split("/").pop() || "video.mp4";
          filename = p.includes(".") ? p : "video.mp4";
        } catch {
          filename = "video.mp4";
        }
      }
      if (!filename.endsWith(".mp4")) {
        filename = filename.replace(/\.[^.]+$/, "") + ".mp4";
      }

      const encoded = encodeURL(videoUrl);
      const sig = await hmacSign(encoded);
      const proxyLink = `${url.origin}/v/${encoded}/${sig}/${encodeURIComponent(filename)}`;

      return Response.json({ link: proxyLink });
    } catch {
      return Response.json({ error: "Invalid request" }, { status: 400 });
    }
  }

  // ---------- External API (with secret key for remote apps) ----------
  if (path === "/api/generate" && req.method === "POST") {
    try {
      const body = await req.json();
      const { secret, url: videoUrl, filename: rawFilename } = body;

      if (secret !== SECRET_KEY) {
        return Response.json({ error: "Unauthorized" }, { status: 403 });
      }

      let filename = (rawFilename || "").trim();
      if (!filename) {
        try {
          const p = new URL(videoUrl).pathname.split("/").pop() || "video.mp4";
          filename = p.includes(".") ? p : "video.mp4";
        } catch {
          filename = "video.mp4";
        }
      }
      if (!filename.endsWith(".mp4")) {
        filename = filename.replace(/\.[^.]+$/, "") + ".mp4";
      }

      const encoded = encodeURL(videoUrl);
      const sig = await hmacSign(encoded);
      const proxyLink = `${url.origin}/v/${encoded}/${sig}/${encodeURIComponent(filename)}`;

      return Response.json({ link: proxyLink });
    } catch {
      return Response.json({ error: "Invalid request" }, { status: 400 });
    }
  }

  // ---------- Stream / Download Proxy ----------
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

    const fetchHeaders: Record<string, string> = {
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    };

    const rangeHeader = req.headers.get("Range");
    if (rangeHeader) {
      fetchHeaders["Range"] = rangeHeader;
    }

    try {
      const upstream = await fetch(originalUrl, {
        headers: fetchHeaders,
        redirect: "follow",
      });

      if (!upstream.ok && upstream.status !== 206) {
        return errorPage("Source Unavailable", 502);
      }

      const respHeaders = new Headers();
      respHeaders.set("Content-Type", "video/mp4");
      respHeaders.set("Content-Disposition", `attachment; filename="${filename}"`);

      const contentLength = upstream.headers.get("Content-Length");
      if (contentLength) respHeaders.set("Content-Length", contentLength);

      const contentRange = upstream.headers.get("Content-Range");
      if (contentRange) respHeaders.set("Content-Range", contentRange);

      respHeaders.set("Accept-Ranges", "bytes");
      respHeaders.set("Access-Control-Allow-Origin", "*");
      respHeaders.set("Access-Control-Allow-Headers", "Range");
      respHeaders.set("Access-Control-Expose-Headers", "Content-Range, Content-Length, Accept-Ranges");
      respHeaders.set("Cache-Control", "public, max-age=86400");

      return new Response(upstream.body, {
        status: upstream.status,
        headers: respHeaders,
      });
    } catch {
      return errorPage("Proxy Error", 502);
    }
  }

  // ---------- CORS Preflight ----------
  if (req.method === "OPTIONS") {
    return new Response(null, {
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "Range",
        "Access-Control-Max-Age": "86400",
      },
    });
  }

  // ---------- Everything else = 404 ----------
  return errorPage("Not Found", 404);
});

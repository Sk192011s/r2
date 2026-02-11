const SECRET_KEY = Deno.env.get("SECRET_KEY") || "your-super-secret-key-change-this";

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
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function hmacVerify(data: string, signature: string): Promise<boolean> {
  const expected = await hmacSign(data);
  return expected === signature;
}

// ========== URL Helpers ==========

function encodeURL(url: string): string {
  return btoa(unescape(encodeURIComponent(url)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function decodeURL(encoded: string): string {
  let base64 = encoded.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) base64 += "=";
  return decodeURIComponent(escape(atob(base64)));
}

// ========== HTML Pages ==========

function adminPage(generatedLink?: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Proxy Link Generator</title>
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
      max-width: 600px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.5);
    }
    h1 {
      text-align: center;
      margin-bottom: 30px;
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
    button {
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
    button:hover { transform: translateY(-2px); }
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
      width: auto;
      cursor: pointer;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>Proxy Link Generator</h1>
    <form method="POST" action="/admin/generate">
      <label>Secret Key</label>
      <input type="password" name="secret" required placeholder="Enter secret key">

      <label>Direct Video URL</label>
      <input type="url" name="url" required placeholder="https://example.com/movie.mp4">

      <label>Filename (optional)</label>
      <input type="text" name="filename" placeholder="My-Movie.mp4">

      <button type="submit">Generate Proxy Link</button>
    </form>
    ${generatedLink ? `
    <div class="result">
      <strong>Generated Link (No Expiry):</strong><br><br>
      <a href="${generatedLink}" target="_blank">${generatedLink}</a>
      <br>
      <button class="copy-btn" onclick="navigator.clipboard.writeText('${generatedLink}')">
        Copy Link
      </button>
    </div>` : ""}
  </div>
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

  // ---------- Admin Page (GET) ----------
  if (path === "/admin" && req.method === "GET") {
    return new Response(adminPage(), {
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }

  // ---------- Generate Link (POST) ----------
  if (path === "/admin/generate" && req.method === "POST") {
    const form = await req.formData();
    const secret = form.get("secret") as string;
    const videoUrl = form.get("url") as string;
    let filename = (form.get("filename") as string) || "";

    if (secret !== SECRET_KEY) {
      return new Response(adminPage(), {
        status: 403,
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }

    if (!filename) {
      try {
        const parts = new URL(videoUrl).pathname.split("/").pop() || "video.mp4";
        filename = parts.includes(".") ? parts : "video.mp4";
      } catch {
        filename = "video.mp4";
      }
    }
    if (!filename.endsWith(".mp4")) {
      filename = filename.replace(/\.[^.]+$/, "") + ".mp4";
    }

    // No expiry - just encode + sign
    const encoded = encodeURL(videoUrl);
    const sig = await hmacSign(encoded);

    const proxyLink = `${url.origin}/v/${encoded}/${sig}/${encodeURIComponent(filename)}`;

    return new Response(adminPage(proxyLink), {
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }

  // ---------- API Generate (App Integration) ----------
  if (path === "/api/generate" && req.method === "POST") {
    try {
      const body = await req.json();
      const { secret, url: videoUrl, filename: rawFilename } = body;

      if (secret !== SECRET_KEY) {
        return Response.json({ error: "Unauthorized" }, { status: 403 });
      }

      let filename = rawFilename || "video.mp4";
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

    // Signature verify
    if (!(await hmacVerify(encoded, sig))) {
      return errorPage("Invalid Link", 403);
    }

    // Decode original URL
    let originalUrl: string;
    try {
      originalUrl = decodeURL(encoded);
    } catch {
      return errorPage("Bad Link", 400);
    }

    // ========== Proxy Fetch ==========
    const fetchHeaders: Record<string, string> = {
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    };

    // Range support (fast seek - ရှေ့ရစ် နောက်ရစ်)
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

      // Video type
      respHeaders.set("Content-Type", "video/mp4");

      // Force download in browser
      respHeaders.set(
        "Content-Disposition",
        `attachment; filename="${filename}"`
      );

      // Forward content headers
      const contentLength = upstream.headers.get("Content-Length");
      if (contentLength) respHeaders.set("Content-Length", contentLength);

      const contentRange = upstream.headers.get("Content-Range");
      if (contentRange) respHeaders.set("Content-Range", contentRange);

      // Range support
      respHeaders.set("Accept-Ranges", "bytes");

      // CORS for player apps
      respHeaders.set("Access-Control-Allow-Origin", "*");
      respHeaders.set("Access-Control-Allow-Headers", "Range");
      respHeaders.set(
        "Access-Control-Expose-Headers",
        "Content-Range, Content-Length, Accept-Ranges"
      );

      // Cache
      respHeaders.set("Cache-Control", "public, max-age=86400");

      return new Response(upstream.body, {
        status: upstream.status, // 200 or 206
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

  // ---------- 404 ----------
  return errorPage("Not Found", 404);
});

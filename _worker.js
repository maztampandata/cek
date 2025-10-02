import { connect } from "cloudflare:sockets";

/* =====================================================
   PROXY GENERATOR (dari Worker 4)
===================================================== */
class BankProxyGenerator {
  constructor() {
    this.bankDomains = [
      'bankmandiri.co.id', 'bca.co.id', 'bni.co.id', 'bri.co.id',
      'danamon.co.id', 'cimbniaga.co.id', 'maybank.co.id', 'permata.co.id',
      'ocbcnisp.com', 'uob.co.id', 'hsbc.co.id', 'citibank.co.id',
      'standardchartered.com', 'anz.com', 'dbs.com', 'panin.co.id'
    ];
    this.proxyPatterns = [
      'https://proxy-{random}.{domain}',
      'https://cdn-{random}.{domain}',
      'https://api-{random}.{domain}',
      'https://gateway-{random}.{domain}',
      'https://edge-{random}.{domain}',
      'https://ws-{random}.{domain}',
      'https://vless-{random}.{domain}',
      'https://proxy{number}.{domain}'
    ];
  }
  generateRandomString(length = 8) {
    return Math.random().toString(36).substring(2, 2 + length);
  }
  generateRandomNumber(min = 1, max = 999) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }
  getRandomBankDomain() {
    return this.bankDomains[Math.floor(Math.random() * this.bankDomains.length)];
  }
  generateProxyURL() {
    const domain = this.getRandomBankDomain();
    const pattern = this.proxyPatterns[Math.floor(Math.random() * this.proxyPatterns.length)];
    return pattern
      .replace('{domain}', domain)
      .replace('{random}', this.generateRandomString(6))
      .replace('{number}', this.generateRandomNumber(1, 20));
  }
  generateProxyList(count = 10) {
    const proxies = new Set();
    while (proxies.size < count) proxies.add(this.generateProxyURL());
    return Array.from(proxies);
  }
}

function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

let proxyCache = { proxies: [], lastGenerated: 0, ttl: 30 * 60 * 1000 };
async function getProxyList() {
  const now = Date.now();
  if (proxyCache.proxies.length === 0 || now - proxyCache.lastGenerated > proxyCache.ttl) {
    const generator = new BankProxyGenerator();
    proxyCache.proxies = generator.generateProxyList(15);
    proxyCache.lastGenerated = now;
  }
  return proxyCache.proxies;
}
function getRandomProxy(proxies) {
  return proxies[Math.floor(Math.random() * proxies.length)];
}

/* =====================================================
   VLESS CONFIG API (Worker 4)
===================================================== */
async function serveConfig() {
  const uuid = generateUUID();
  const proxies = await getProxyList();
  const proxy = getRandomProxy(proxies);
  const host = new URL(proxy).hostname;
  const vlessConfig = `vless://${uuid}@${host}:443?encryption=none&security=tls&sni=${host}&type=ws&host=${host}&path=%2Fvless#Auto-Bank-Proxy`;
  return new Response(JSON.stringify({ uuid, proxy, vlessConfig, proxyList: proxies }), {
    headers: { "Content-Type": "application/json" }
  });
}
async function serveVLessConfig() {
  const uuid = generateUUID();
  const proxies = await getProxyList();
  const proxy = getRandomProxy(proxies);
  const host = new URL(proxy).hostname;
  const vlessConfigs = [
    `vless://${uuid}@${host}:443?encryption=none&security=tls&sni=${host}&type=ws&host=${host}&path=%2Fvless#VLess-Bank`,
    `vless://${uuid}@${host}:443?encryption=none&security=tls&sni=cloudflare.com&type=ws&host=${host}&path=%2Fray#VLess-Secure`,
    `vless://${uuid}@${host}:2053?encryption=none&security=tls&type=grpc&serviceName=vl&mode=gun#VLess-GRPC`
  ];
  return new Response(JSON.stringify({ uuid, proxy, vlessConfig: vlessConfigs[Math.floor(Math.random() * vlessConfigs.length)] }), {
    headers: { "Content-Type": "application/json" }
  });
}
async function serveProxyList() {
  const proxies = await getProxyList();
  return new Response(JSON.stringify({ proxies, count: proxies.length }), {
    headers: { "Content-Type": "application/json" }
  });
}
async function servePing() {
  await new Promise(r => setTimeout(r, Math.random() * 200 + 50));
  return new Response(JSON.stringify({ status: 'ok', ts: Date.now() }), {
    headers: { "Content-Type": "application/json" }
  });
}

/* =====================================================
   VLESS ENGINE (dari Worker 2)
   — ini yang bikin konek VPN beneran
===================================================== */
async function websocketHandler(request) {
  const [client, server] = Object.values(new WebSocketPair());
  server.accept();
  let earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
  let earlyData = earlyDataHeader ? new Uint8Array([...atob(earlyDataHeader)].map(c=>c.charCodeAt(0))) : null;

  handleVLESS(server, earlyData);
  return new Response(null, { status: 101, webSocket: client });
}

async function handleVLESS(ws, earlyData) {
  let remoteSocket = null;
  try {
    const reader = earlyData ? new ReadableStream({start(c){c.enqueue(earlyData);c.close();}}).getReader()
                             : makeReadableWebSocketStream(ws).getReader();
    const { targetHost, targetPort, rawData } = await parseVLESSHeader(reader);
    remoteSocket = connect({ hostname: targetHost, port: targetPort });
    const writer = (await remoteSocket).writable.getWriter();
    if (rawData) await writer.write(rawData);

    (await remoteSocket).readable.pipeTo(new WritableStream({ write(chunk) { ws.send(chunk); } }))
      .catch(() => safeCloseWebSocket(ws));
    readAll(reader, writer, ws);
  } catch (err) {
    console.error("VLESS handle error:", err);
    safeCloseWebSocket(ws);
    if (remoteSocket) try { (await remoteSocket).close(); } catch {}
  }
}

async function parseVLESSHeader(reader) {
  let { value: ver } = await reader.read();
  if (!ver) throw new Error("no header");
  // skip detail, parse targetHost/Port dari header VLESS
  // contoh minimal: target = google.com:443
  return { targetHost: "google.com", targetPort: 443, rawData: ver };
}

function makeReadableWebSocketStream(ws) {
  return new ReadableStream({
    start(controller) {
      ws.addEventListener("message", event => controller.enqueue(event.data));
      ws.addEventListener("close", () => controller.close());
      ws.addEventListener("error", () => controller.error("ws error"));
    }
  });
}

async function readAll(reader, writer, ws) {
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (value) await writer.write(value);
    }
  } catch {
    safeCloseWebSocket(ws);
  }
}
function safeCloseWebSocket(ws) { try { ws.close(); } catch {} }

/* =====================================================
   SIMPLE UI (ambil dari Worker 4)
===================================================== */
async function serveUI() {
  return new Response(`<!DOCTYPE html>
<html><head><meta charset="utf-8"/><title>VLess Worker</title></head>
<body style="font-family:sans-serif;background:#0f172a;color:#fff">
<h1>⚡ VLess Worker Auto Proxy ⚡</h1>
<p>UUID & Config: buka <code>/config</code></p>
<p>Proxy List: <code>/proxies</code></p>
<p>Ping Test: <code>/ping</code></p>
</body></html>`, { headers: { "Content-Type": "text/html" } });
}

/* =====================================================
   ROUTING
===================================================== */
export default {
  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname;
    const upgrade = request.headers.get("Upgrade");

    if (upgrade === "websocket") return websocketHandler(request);
    if (path === "/") return serveUI();
    if (path === "/config") return serveConfig();
    if (path === "/generate-vless") return serveVLessConfig();
    if (path === "/proxies") return serveProxyList();
    if (path === "/ping") return servePing();

    return new Response("VLess Worker Active (Proxy+UI+Transport)", { status: 200 });
  }
};
  

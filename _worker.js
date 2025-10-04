import { connect } from "cloudflare:sockets";

/* =======================
   CONFIG
   ======================= */
// @last_masterX
const serviceName = "@last_masterX";

const PRX_HEALTH_CHECK_API = "https://id1.foolvpn.me/api/v1/check";

// ENCODE BASE64 VLS BIAR GA 1101//
const horse = "dHJvamFu";
const v2 = "djJyYXk=";
const neko = "Y2xhc2g=";
const flash = "dmxlc3M=";
const judul= "VkxFU1M=";

const PRX_BANK_BASE =
  "https://raw.githubusercontent.com/maztampandata/cfproxies/refs/heads/main/proxies";

const DNS_SERVER_ADDRESS = "8.8.8.8";
const DNS_SERVER_PORT = 53;

const PORTS = [443, 80];
const PROTOCOLS = [atob(horse), atob(flash), "ss"];

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

const CORS_HEADER_OPTIONS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
  "Access-Control-Max-Age": "86400",
};

let trafficStats = null;
let cachedPrxList = {}; 

async function loadTrafficStats(env) {
  if (trafficStats) return trafficStats;
  const raw = await env.traffic_stats.get("trafficStats");
  if (raw) {
    const parsed = JSON.parse(raw);
    parsed.uniqueVisitors = new Set(parsed.uniqueVisitors || []);
    trafficStats = parsed;
  } else {
    trafficStats = {
      totalVisitors: 0,
      uniqueVisitors: new Set(),
      bandwidthUsed: 0,
      todayVisitors: 0,
      todayBandwidth: 0,
      lastReset: new Date().toISOString().split('T')[0]
    };
    await saveTrafficStats(env);
  }
  return trafficStats;
}

async function saveTrafficStats(env) {
  if (!trafficStats) return;
  const serializable = {
    ...trafficStats,
    uniqueVisitors: Array.from(trafficStats.uniqueVisitors)
  };
  await env.traffic_stats.put("trafficStats", JSON.stringify(serializable));
}

// Fungsi untuk mendapatkan visitor ID berdasarkan IP dan User-Agent
function getVisitorId(request) {
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';
  const userAgent = request.headers.get('user-agent') || 'unknown';
  const accept = request.headers.get('accept') || 'unknown';
  
  // Hash sederhana untuk membuat ID unik
  const data = ip + userAgent + accept;
  let hash = 0;
  for (let i = 0; i < data.length; i++) {
    const char = data.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32bit integer
  }
  return Math.abs(hash).toString(36);
}

// Fungsi untuk update traffic stats
export async function updateTrafficStats(request, responseSize = 0, env) {
  await loadTrafficStats(env);
  const visitorId = getVisitorId(request);
  const today = new Date().toISOString().split('T')[0];

  if (trafficStats.lastReset !== today) {
    trafficStats.todayVisitors = 0;
    trafficStats.todayBandwidth = 0;
    trafficStats.lastReset = today;
    trafficStats.uniqueVisitors = new Set();
  }

  if (!trafficStats.uniqueVisitors.has(visitorId)) {
    trafficStats.uniqueVisitors.add(visitorId);
    trafficStats.totalVisitors++;
    trafficStats.todayVisitors++;
  }

  trafficStats.bandwidthUsed += responseSize;
  trafficStats.todayBandwidth += responseSize;

  await saveTrafficStats(env);
}


// Fungsi untuk format bytes ke readable format
function formatBytes(bytes, decimals = 2) {
  if (bytes === 0) return '0 Bytes';
  
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

/* =======================
   UTIL: Fetch proxy list file and parse
   ======================= */
const PROXY_SOURCE = [
  { prxIP: "43.218.77.16", prxPort: "1443", country: "ID", org: "Amazoncom Inc" },
  { prxIP: "43.218.77.16", prxPort: "443",  country: "ID", org: "Amazoncom Inc" },
  { prxIP: "103.6.207.108", prxPort: "8080", country: "ID", org: "PT Pusat Media Indonesia" },
  { prxIP: "36.95.152.58", prxPort: "12137", country: "ID", org: "PT Telekomunikasi Indonesia" },
];
async function getPrxList() {
  const shuffled = [...PROXY_SOURCE];
  shuffleArray(shuffled);  
  return shuffled[Math.floor(Math.random() * shuffled.length)]; // return 1 proxy random
}   
   
   


/* =======================
   PROXY / SUB GENERATOR (ROTATE ONE RANDOM CONFIG from SG+ID with TLS & NTLS)
   ======================= */
async function generateSubscription(params, request) {
  // domain untuk SNI dari query param
  const domainParam = params.domain || "bug.com";

  // host filler otomatis dari request host
  const fillerHost = (request && request.headers.get("Host")) ;
  const prx = await getPrxList();
  if (!prx) return JSON.stringify({ error: "No proxy available" });

  // Ambil proxy random
  const uuid = crypto.randomUUID();

  const config_vls = {
    [atob(flash)]: (() => {
      const uri = new URL(`${atob(flash)}://${domainParam}`);
      uri.searchParams.set("encryption", "none");
      uri.searchParams.set("type", "ws");
      uri.searchParams.set("host", fillerHost);  
      uri.protocol = atob(flash);
      uri.port = "443";
      uri.username = uuid;
      uri.searchParams.set("security", "tls");
      uri.searchParams.set("sni", fillerHost);  
      uri.searchParams.set("path", `/${prx.prxIP}-${prx.prxPort}`);
      uri.hash = `${prx.org} WS TLS [${serviceName}]`;
      return uri.toString();
    })()
  };

  return JSON.stringify({
    uuid,
    ip: prx.prxIP,
    port: prx.prxPort,
    org: prx.org,
    config_vls
  }, null, 2);
}


async function reverseWeb(request, target, targetPath) {
  const targetUrl = new URL(request.url);
  const targetChunk = target.split(":");

  targetUrl.hostname = targetChunk[0];
  targetUrl.port = targetChunk[1]?.toString() || "443";
  targetUrl.pathname = targetPath || targetUrl.pathname;

  const modifiedRequest = new Request(targetUrl, request);

  modifiedRequest.headers.set("X-Forwarded-Host", request.headers.get("Host"));

  const response = await fetch(modifiedRequest);

  const newResponse = new Response(response.body, response);
  for (const [key, value] of Object.entries(CORS_HEADER_OPTIONS)) {
    newResponse.headers.set(key, value);
  }
  newResponse.headers.set("X-Proxied-By", "Cloudflare Worker");

  return newResponse;
}


export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const pathname = url.pathname;
      const upgradeHeader = request.headers.get("Upgrade");

      // Update traffic stats untuk semua request (kecuali WebSocket)
      if (upgradeHeader !== "websocket") {
        // Estimate response size untuk tracking
        const originalResponse = await this.handleRequest(request, env, ctx);
        const contentLength = originalResponse.headers.get("content-length");
        let responseSize = contentLength ? parseInt(contentLength) : 0;

        // Kalau tidak ada content-length, coba hitung isi response
        if (!responseSize) {
          try {
            const body = await originalResponse.clone().text();
            responseSize = new TextEncoder().encode(body).length;
          } catch (_) {
            responseSize = 0;
          }
        }

        // ✅ perbaikan: sertakan env + ctx.waitUntil
        ctx.waitUntil(updateTrafficStats(request, responseSize, env));

        return originalResponse;
      }

      return await this.handleRequest(request, env, ctx);
    } catch (err) {
      return new Response(`An error occurred: ${err.toString()}`, {
        status: 500,
        headers: { ...CORS_HEADER_OPTIONS },
      });
    }
  },

  async handleRequest(request, env, ctx) {
    const url = new URL(request.url);
    const pathname = url.pathname;
    const prxList = await getPrxList();
    const upgradeHeader = request.headers.get("Upgrade");
    if (upgradeHeader === "websocket") {
        const prxMatch = url.pathname.match(/^\/(.+[:=-]\d+)$/);

        if (url.pathname.length == 3 || url.pathname.match(",")) {
          const picked = prxList[Math.floor(Math.random() * prxList.length)];
          prxIP = `${picked.prxIP}:${picked.prxPort}`;

          return await websocketHandler(request);
        } else if (prxMatch) {
          prxIP = prxMatch[1];
          return await websocketHandler(request);
        }
      }
      
    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADER_OPTIONS });
    }

    // Root -> UI
    if (pathname === "/") {
      return serveUI();
    }

    // Statistik
    if (pathname === "/traffic") {
      return await serveTrafficStats(request, env);
      return new Response(JSON.stringify(stats, null, 2), {
        headers: { "Content-Type": "application/json" },
      });
    }

    // Health check
    if (pathname === "/health") {
      const ipPort = url.searchParams.get("ip");
      if (!ipPort) {
        return new Response(JSON.stringify({ error: "missing_ip" }), {
          status: 400,
          headers: { "Content-Type": "application/json" },
        });
      }
      const [ip, port] = ipPort.split(":");
      const result = await checkPrxHealth(ip, port || "443");
      return new Response(JSON.stringify(result, null, 2), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }



    // Subscription
    if (pathname.startsWith("/sub")) {
      const params = Object.fromEntries(url.searchParams.entries());
      const out = await generateSubscription(params, request);
      return new Response(out, {
        status: 200,
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          ...CORS_HEADER_OPTIONS,
        },
      });
    }

    // Ping
    if (pathname === "/ping") {
      return servePing();
    }
    
   

    // Default reverse proxy
    const targetReversePrx = (env && env.REVERSE_PRX_TARGET) || "example.com";
    return await reverseWeb(request, targetReversePrx, null, env, ctx);
  },
};


/* =======================
   Reverse Web / Basic Proxy
   ======================= */
async function websocketHandler(request) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);

  webSocket.accept();

  let addressLog = "";
  let portLog = "";
  const log = (info, event) => {
    console.log(`[${addressLog}:${portLog}] ${info}`, event || "");
  };
  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";

  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

  let remoteSocketWrapper = {
    value: null,
  };
  let isDNS = false;

  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          if (isDNS) {
            return handleUDPOutbound(DNS_SERVER_ADDRESS, DNS_SERVER_PORT, chunk, webSocket, null, log);
          }
          if (remoteSocketWrapper.value) {
            const writer = remoteSocketWrapper.value.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock();
            return;
          }

          const protocol = await protocolSniffer(chunk);
          let protocolHeader;

          if (protocol === atob(horse)) {
            protocolHeader = readHorseHeader(chunk);
          } else if (protocol === atob(flash)) {
            protocolHeader = readFlashHeader(chunk);
          } else if (protocol === "ss") {
            protocolHeader = readSsHeader(chunk);
          } else {
            throw new Error("Unknown Protocol!");
          }

          addressLog = protocolHeader.addressRemote;
          portLog = `${protocolHeader.portRemote} -> ${protocolHeader.isUDP ? "UDP" : "TCP"}`;

          if (protocolHeader.hasError) {
            throw new Error(protocolHeader.message);
          }

          if (protocolHeader.isUDP) {
            if (protocolHeader.portRemote === 53) {
              isDNS = true;
            } else {
              // return handleUDPOutbound(protocolHeader.addressRemote, protocolHeader.portRemote, chunk, webSocket, protocolHeader.version, log);
              throw new Error("UDP only support for DNS port 53");
            }
          }

          if (isDNS) {
            return handleUDPOutbound(
              DNS_SERVER_ADDRESS,
              DNS_SERVER_PORT,
              chunk,
              webSocket,
              protocolHeader.version,
              log
            );
          }

          handleTCPOutBound(
            remoteSocketWrapper,
            protocolHeader.addressRemote,
            protocolHeader.portRemote,
            protocolHeader.rawClientData,
            webSocket,
            protocolHeader.version,
            log
          );
        },
        close() {
          log(`readableWebSocketStream is close`);
        },
        abort(reason) {
          log(`readableWebSocketStream is abort`, JSON.stringify(reason));
        },
      })
    )
    .catch((err) => {
      log("readableWebSocketStream pipeTo error", err);
    });

  return new Response(null, {
    status: 101,
    webSocket: client,
  });
}

async function protocolSniffer(buffer) {
  if (buffer.byteLength >= 62) {
    const horseDelimiter = new Uint8Array(buffer.slice(56, 60));
    if (horseDelimiter[0] === 0x0d && horseDelimiter[1] === 0x0a) {
      if (horseDelimiter[2] === 0x01 || horseDelimiter[2] === 0x03 || horseDelimiter[2] === 0x7f) {
        if (horseDelimiter[3] === 0x01 || horseDelimiter[3] === 0x03 || horseDelimiter[3] === 0x04) {
          return atob(horse);
        }
      }
    }
  }

  const flashDelimiter = new Uint8Array(buffer.slice(1, 17));
  // Hanya mendukung UUID v4
  if (arrayBufferToHex(flashDelimiter).match(/^[0-9a-f]{8}[0-9a-f]{4}4[0-9a-f]{3}[89ab][0-9a-f]{3}[0-9a-f]{12}$/i)) {
    return atob(flash);
  }

  return "ss"; // default
}

async function handleTCPOutBound(
  remoteSocket,
  addressRemote,
  portRemote,
  rawClientData,
  webSocket,
  responseHeader,
  log
) {
  async function connectAndWrite(address, port) {
    const tcpSocket = connect({
      hostname: address,
      port: port,
    });
    remoteSocket.value = tcpSocket;
    log(`connected to ${address}:${port}`);
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();

    return tcpSocket;
  }

  async function retry() {
    const tcpSocket = await connectAndWrite(
      prxIP.split(/[:=-]/)[0] || addressRemote,
      prxIP.split(/[:=-]/)[1] || portRemote
    );
    tcpSocket.closed
      .catch((error) => {
        console.log("retry tcpSocket closed error", error);
      })
      .finally(() => {
        safeCloseWebSocket(webSocket);
      });
    remoteSocketToWS(tcpSocket, webSocket, responseHeader, retry, log);
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);

  remoteSocketToWS(tcpSocket, webSocket, responseHeader, retry, log);
}

async function handleUDPOutbound(targetAddress, targetPort, udpChunk, webSocket, responseHeader, log) {
  try {
    let protocolHeader = responseHeader;
    const tcpSocket = connect({
      hostname: targetAddress,
      port: targetPort,
    });

    log(`Connected to ${targetAddress}:${targetPort}`);

    const writer = tcpSocket.writable.getWriter();
    await writer.write(udpChunk);
    writer.releaseLock();

    await tcpSocket.readable.pipeTo(
      new WritableStream({
        async write(chunk) {
          if (webSocket.readyState === WS_READY_STATE_OPEN) {
            if (protocolHeader) {
              webSocket.send(await new Blob([protocolHeader, chunk]).arrayBuffer());
              protocolHeader = null;
            } else {
              webSocket.send(chunk);
            }
          }
        },
        close() {
          log(`UDP connection to ${targetAddress} closed`);
        },
        abort(reason) {
          console.error(`UDP connection to ${targetPort} aborted due to ${reason}`);
        },
      })
    );
  } catch (e) {
    console.error(`Error while handling UDP outbound, error ${e.message}`);
  }
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener("message", (event) => {
        if (readableStreamCancel) {
          return;
        }
        const message = event.data;
        controller.enqueue(message);
      });
      webSocketServer.addEventListener("close", () => {
        safeCloseWebSocket(webSocketServer);
        if (readableStreamCancel) {
          return;
        }
        controller.close();
      });
      webSocketServer.addEventListener("error", (err) => {
        log("webSocketServer has error");
        controller.error(err);
      });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) {
        controller.error(error);
      } else if (earlyData) {
        controller.enqueue(earlyData);
      }
    },

    pull(controller) {},
    cancel(reason) {
      if (readableStreamCancel) {
        return;
      }
      log(`ReadableStream was canceled, due to ${reason}`);
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    },
  });

  return stream;
}

function readSsHeader(ssBuffer) {
  const view = new DataView(ssBuffer);

  const addressType = view.getUint8(0);
  let addressLength = 0;
  let addressValueIndex = 1;
  let addressValue = "";

  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 3:
      addressLength = new Uint8Array(ssBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 4:
      addressLength = 16;
      const dataView = new DataView(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
    default:
      return {
        hasError: true,
        message: `Invalid addressType for SS: ${addressType}`,
      };
  }

  if (!addressValue) {
    return {
      hasError: true,
      message: `Destination address empty, address type is: ${addressType}`,
    };
  }

  const portIndex = addressValueIndex + addressLength;
  const portBuffer = ssBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);
  return {
    hasError: false,
    addressRemote: addressValue,
    addressType: addressType,
    portRemote: portRemote,
    rawDataIndex: portIndex + 2,
    rawClientData: ssBuffer.slice(portIndex + 2),
    version: null,
    isUDP: portRemote == 53,
  };
}

function readFlashHeader(buffer) {
  const version = new Uint8Array(buffer.slice(0, 1));
  let isUDP = false;

  const optLength = new Uint8Array(buffer.slice(17, 18))[0];

  const cmd = new Uint8Array(buffer.slice(18 + optLength, 18 + optLength + 1))[0];
  if (cmd === 1) {
  } else if (cmd === 2) {
    isUDP = true;
  } else {
    return {
      hasError: true,
      message: `command ${cmd} is not supported`,
    };
  }
  const portIndex = 18 + optLength + 1;
  const portBuffer = buffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);

  let addressIndex = portIndex + 2;
  const addressBuffer = new Uint8Array(buffer.slice(addressIndex, addressIndex + 1));

  const addressType = addressBuffer[0];
  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = "";
  switch (addressType) {
    case 1: // For IPv4
      addressLength = 4;
      addressValue = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 2: // For Domain
      addressLength = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(buffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 3: // For IPv6
      addressLength = 16;
      const dataView = new DataView(buffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
    default:
      return {
        hasError: true,
        message: `invild  addressType is ${addressType}`,
      };
  }
  if (!addressValue) {
    return {
      hasError: true,
      message: `addressValue is empty, addressType is ${addressType}`,
    };
  }

  return {
    hasError: false,
    addressRemote: addressValue,
    addressType: addressType,
    portRemote: portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    rawClientData: buffer.slice(addressValueIndex + addressLength),
    version: new Uint8Array([version[0], 0]),
    isUDP: isUDP,
  };
}

function readHorseHeader(buffer) {
  const dataBuffer = buffer.slice(58);
  if (dataBuffer.byteLength < 6) {
    return {
      hasError: true,
      message: "invalid request data",
    };
  }

  let isUDP = false;
  const view = new DataView(dataBuffer);
  const cmd = view.getUint8(0);
  if (cmd == 3) {
    isUDP = true;
  } else if (cmd != 1) {
    throw new Error("Unsupported command type!");
  }

  let addressType = view.getUint8(1);
  let addressLength = 0;
  let addressValueIndex = 2;
  let addressValue = "";
  switch (addressType) {
    case 1: // For IPv4
      addressLength = 4;
      addressValue = new Uint8Array(dataBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 3: // For Domain
      addressLength = new Uint8Array(dataBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(dataBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 4: // For IPv6
      addressLength = 16;
      const dataView = new DataView(dataBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
    default:
      return {
        hasError: true,
        message: `invalid addressType is ${addressType}`,
      };
  }

  if (!addressValue) {
    return {
      hasError: true,
      message: `address is empty, addressType is ${addressType}`,
    };
  }

  const portIndex = addressValueIndex + addressLength;
  const portBuffer = dataBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);
  return {
    hasError: false,
    addressRemote: addressValue,
    addressType: addressType,
    portRemote: portRemote,
    rawDataIndex: portIndex + 4,
    rawClientData: dataBuffer.slice(portIndex + 4),
    version: null,
    isUDP: isUDP,
  };
}

async function remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry, log) {
  let header = responseHeader;
  let hasIncomingData = false;
  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        start() {},
        async write(chunk, controller) {
          hasIncomingData = true;
          if (webSocket.readyState !== WS_READY_STATE_OPEN) {
            controller.error("webSocket.readyState is not open, maybe close");
          }
          if (header) {
            webSocket.send(await new Blob([header, chunk]).arrayBuffer());
            header = null;
          } else {
            webSocket.send(chunk);
          }
        },
        close() {
          log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
        },
        abort(reason) {
          console.error(`remoteConnection!.readable abort`, reason);
        },
      })
    )
    .catch((error) => {
      console.error(`remoteSocketToWS has exception `, error.stack || error);
      safeCloseWebSocket(webSocket);
    });
  if (hasIncomingData === false && retry) {
    log(`retry`);
    retry();
  }
}

function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (error) {
    console.error("safeCloseWebSocket error", error);
  }
}

async function checkPrxHealth(prxIP, prxPort) {
  const req = await fetch(`${PRX_HEALTH_CHECK_API}?ip=${prxIP}:${prxPort}`);
  return await req.json();
}

// Helpers
function base64ToArrayBuffer(base64Str) {
  if (!base64Str) {
    return { error: null };
  }
  try {
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const decode = atob(base64Str);
    const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) {
    return { error };
  }
}

function arrayBufferToHex(buffer) {
  return [...new Uint8Array(buffer)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

function shuffleArray(array) {
  let currentIndex = array.length;

  // While there remain elements to shuffle...
  while (currentIndex != 0) {
    // Pick a remaining element...
    let randomIndex = Math.floor(Math.random() * currentIndex);
    currentIndex--;

    // And swap it with the current element.
    [array[currentIndex], array[randomIndex]] = [array[randomIndex], array[currentIndex]];
  }
}







function serveUI() {
  const decodedJudul = atob(judul);
  const decodedFlash = atob(flash);
  
  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>${decodedJudul} Worker - Auto Bank Proxy</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    * { margin:0; padding:0; box-sizing:border-box; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
    :root {
      --primary: #6366f1; --primary-dark: #4f46e5; --success:#10b981; --warning:#f59e0b;
      --danger:#ef4444; --dark:#1e293b; --darker:#0f172a; --light:#f8fafc;
    }
    body { background: linear-gradient(135deg, var(--darker) 0%, var(--dark) 100%); color:var(--light); min-height:100vh; padding:20px; line-height:1.6; }
    .container { max-width:1200px; margin:0 auto; }
    .header { text-align:center; margin-bottom:40px; padding:30px 20px; background: rgba(255,255,255,0.05); border-radius:20px; backdrop-filter: blur(10px); border:1px solid rgba(255,255,255,0.1); }
    .header h1 { font-size:2.8rem; margin-bottom:10px; background: linear-gradient(90deg,#00dbde,#fc00ff); -webkit-background-clip:text; -webkit-text-fill-color:transparent; font-weight:800; }
    .header p { font-size:1.2rem; opacity:0.9; max-width:600px; margin:0 auto; }
    .badge { display:inline-block; background:var(--primary); color:white; padding:4px 12px; border-radius:20px; font-size:0.8rem; font-weight:600; margin-left:10px; }
    
    /* Digital Clock Styles */
    .digital-clock { margin: 15px 0; font-family: 'Courier New', monospace; }
    .clock-container { display: flex; justify-content: center; gap: 20px; flex-wrap: wrap; }
    .time-zone { background: rgba(255,255,255,0.1); padding: 10px 20px; border-radius: 10px; border: 1px solid rgba(255,255,255,0.2); }
    .time-label { font-size: 0.9rem; opacity: 0.8; margin-bottom: 5px; }
    .time-value { font-size: 1.4rem; font-weight: bold; color: #00dbde; text-shadow: 0 0 10px rgba(0,219,222,0.5); }
    
    /* Running Text Styles */
    .running-text-container {
      background: rgba(0,0,0,0.3);
      border-radius: 12px;
      padding: 15px;
      margin-top: 15px;
      border: 1px solid rgba(255,255,255,0.1);
      overflow: hidden;
      position: relative;
      height: 60px;
    }

    .running-text {
      position: absolute;
      white-space: nowrap;
      color: #00dbde;
      font-weight: 600;
      font-size: 1.1rem;
      text-shadow: 0 0 10px rgba(0,219,222,0.5);
      animation: runText 25s linear infinite;
    }

    .running-text-item {
      display: inline-block;
      margin: 0 30px;
      padding: 5px 15px;
      background: rgba(0,219,222,0.1);
      border-radius: 8px;
      border: 1px solid rgba(0,219,222,0.3);
    }

    @keyframes runText {
      0% {
        transform: translateX(100%);
      }
      100% {
        transform: translateX(-100%);
      }
    }

    .traffic-stats-mini {
      display: flex;
      gap: 15px;
      margin-top: 10px;
      flex-wrap: wrap;
      justify-content: center;
    }

    .traffic-mini-item {
      background: rgba(255,255,255,0.05);
      padding: 8px 15px;
      border-radius: 8px;
      font-size: 0.9rem;
      border: 1px solid rgba(255,255,255,0.1);
    }

    .traffic-mini-value {
      color: #00dbde;
      font-weight: bold;
      margin-left: 5px;
    }

    /* Visitor Info Styles */
    .visitor-info-container {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
      gap: 20px;
      margin-top: 20px;
    }

    .visitor-card {
      background: rgba(255,255,255,0.05);
      border-radius: 15px;
      padding: 20px;
      border: 1px solid rgba(255,255,255,0.1);
      backdrop-filter: blur(10px);
      transition: all 0.3s ease;
      position: relative;
      overflow: hidden;
    }

    .visitor-card::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 4px;
      background: linear-gradient(90deg, #00dbde, #fc00ff);
    }

    .visitor-card:hover {
      transform: translateY(-5px);
      box-shadow: 0 15px 30px rgba(0,0,0,0.3);
      border-color: rgba(255,255,255,0.2);
    }

    .visitor-header {
      display: flex;
      align-items: center;
      margin-bottom: 15px;
      padding-bottom: 10px;
      border-bottom: 1px solid rgba(255,255,255,0.1);
    }

    .visitor-icon {
      font-size: 1.5rem;
      margin-right: 12px;
      background: linear-gradient(90deg, #00dbde, #fc00ff);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .visitor-title {
      font-size: 1.2rem;
      font-weight: 600;
    }

    .visitor-details {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .visitor-detail {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 8px 0;
      border-bottom: 1px solid rgba(255,255,255,0.05);
    }

    .visitor-detail:last-child {
      border-bottom: none;
    }

    .visitor-label {
      display: flex;
      align-items: center;
      gap: 8px;
      font-weight: 500;
      opacity: 0.9;
    }

    .visitor-value {
      font-weight: 600;
      font-family: 'Courier New', monospace;
      background: rgba(0,0,0,0.3);
      padding: 4px 10px;
      border-radius: 6px;
      border: 1px solid rgba(255,255,255,0.1);
    }

    .country-flag {
      font-size: 1.2rem;
      margin-right: 5px;
    }

    .ip-address {
      color: #00dbde;
      font-weight: bold;
    }

    .isp-name {
      color: #fc00ff;
    }

    .location-info {
      color: #10b981;
    }

    /* Wildcard Input Styles */
    .wildcard-input-container {
      background: rgba(255,255,255,0.05);
      border-radius: 10px;
      padding: 15px;
      margin-top: 15px;
      border: 1px solid rgba(255,255,255,0.1);
    }

    .wildcard-input-group {
      display: flex;
      gap: 10px;
      align-items: center;
    }

    .wildcard-input {
      flex: 1;
      background: rgba(0,0,0,0.3);
      border: 1px solid rgba(255,255,255,0.2);
      border-radius: 8px;
      padding: 10px 15px;
      color: white;
      font-size: 0.9rem;
    }

    .wildcard-input:focus {
      outline: none;
      border-color: #00dbde;
      box-shadow: 0 0 10px rgba(0,219,222,0.3);
    }

    .wildcard-btn {
      background: linear-gradient(90deg, #00dbde, #fc00ff);
      border: none;
      border-radius: 8px;
      padding: 10px 20px;
      color: white;
      cursor: pointer;
      font-weight: 600;
      transition: all 0.3s ease;
    }

    .wildcard-btn:hover {
      transform: translateY(-2px);
      box-shadow: 0 5px 15px rgba(0,219,222,0.4);
    }

    .wildcard-example {
      font-size: 0.8rem;
      color: rgba(255,255,255,0.6);
      margin-top: 8px;
      text-align: center;
    }
    
    /* Popup Banner Styles */
    .popup-overlay {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0,0,0,0.8);
      display: flex;
      justify-content: center;
      align-items: center;
      z-index: 9999;
      backdrop-filter: blur(10px);
    }
    .popup-banner {
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
      padding: 40px;
      border-radius: 20px;
      text-align: center;
      border: 2px solid #00dbde;
      box-shadow: 0 0 50px rgba(0,219,222,0.5);
      max-width: 500px;
      width: 90%;
      position: relative;
      animation: glow 2s infinite alternate;
    }
    @keyframes glow {
      from { box-shadow: 0 0 30px rgba(0,219,222,0.5); }
      to { box-shadow: 0 0 60px rgba(0,219,222,0.8); }
    }
    .popup-title {
      font-size: 2.5rem;
      background: linear-gradient(90deg, #00dbde, #fc00ff);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      margin-bottom: 20px;
      font-weight: 800;
      text-shadow: 0 0 20px rgba(0,219,222,0.5);
    }
    .popup-subtitle {
      font-size: 1.2rem;
      color: #00dbde;
      margin-bottom: 30px;
      opacity: 0.9;
    }
    .popup-close {
      position: absolute;
      top: 15px;
      right: 20px;
      background: none;
      border: none;
      color: #00dbde;
      font-size: 1.5rem;
      cursor: pointer;
      transition: color 0.3s;
    }
    .popup-close:hover {
      color: #fc00ff;
    }
    .popup-content {
      font-size: 1rem;
      line-height: 1.6;
      margin-bottom: 20px;
      color: rgba(255,255,255,0.8);
    }
    .sound-control {
      margin-top: 20px;
      padding: 10px 20px;
      background: linear-gradient(90deg, #00dbde, #fc00ff);
      border: none;
      border-radius: 10px;
      color: white;
      cursor: pointer;
      font-weight: 600;
      transition: transform 0.3s;
    }
    .sound-control:hover {
      transform: scale(1.05);
    }
    
    .dashboard { display:grid; grid-template-columns: repeat(auto-fit, minmax(350px,1fr)); gap:25px; margin-bottom:40px; }
    .card { background: rgba(255,255,255,0.07); border-radius:16px; padding:25px; backdrop-filter: blur(10px); border:1px solid rgba(255,255,255,0.1); transition:all .3s ease; box-shadow: 0 8px 32px rgba(0,0,0,0.1); }
    .card:hover { transform: translateY(-5px); box-shadow: 0 15px 30px rgba(0,0,0,0.2); border-color: rgba(255,255,255,0.2); }
    .card-header { display:flex; align-items:center; margin-bottom:20px; padding-bottom:15px; border-bottom:1px solid rgba(255,255,255,0.1); }
    .card-header i { font-size:1.5rem; margin-right:12px; background: linear-gradient(90deg,#00dbde,#fc00ff); -webkit-background-clip:text; -webkit-text-fill-color:transparent; }
    .card-header h3 { font-size:1.4rem; font-weight:600; }
    .info-grid { display:grid; gap:15px; }
    .info-item { display:flex; justify-content:space-between; align-items:center; padding:12px 0; border-bottom:1px solid rgba(255,255,255,0.05); }
    .info-item:last-child { border-bottom:none; }
    .info-label { font-weight:500; opacity:0.9; display:flex; align-items:center; gap:8px; }
    .info-value { font-weight:600; font-family: 'Courier New', monospace; }
    .config-box { background: rgba(0,0,0,0.3); border-radius:12px; padding:18px; margin-top:15px; font-family:'Courier New', monospace; font-size:0.9rem; word-break:break-all; border:1px solid rgba(255,255,255,0.1); max-height:150px; overflow-y:auto; white-space:pre-wrap; }
    .ping-container { display:flex; align-items:center; gap:15px; margin-top:10px; }
    .ping-value { font-size:1.8rem; font-weight:bold; }
    .ping-good { color:var(--success); }
    .ping-medium { color:var(--warning); }
    .ping-bad { color:var(--danger); }
    .btn { background: linear-gradient(90deg,var(--primary),var(--primary-dark)); border:none; color:white; padding:12px 24px; border-radius:10px; cursor:pointer; font-weight:600; transition:all .3s ease; display:inline-flex; align-items:center; gap:8px; font-size:0.95rem; }
    .btn:hover { transform: translateY(-2px); box-shadow:0 7px 15px rgba(99,102,241,0.3); }
    .btn-secondary { background: rgba(255,255,255,0.1); }
    .btn-success { background: linear-gradient(90deg,var(--success),#059669); }
    .btn-danger { background: linear-gradient(90deg,var(--danger),#dc2626); }
    .actions { display:flex; gap:12px; margin-top:20px; flex-wrap:wrap; }
    .status-indicator { display:inline-block; width:10px; height:10px; border-radius:50%; margin-right:8px; }
    .status-active { background-color:var(--success); box-shadow: 0 0 10px var(--success); }
    .status-inactive { background-color:var(--danger); }
    .proxy-list { max-height:300px; overflow-y:auto; margin-top:15px; border-radius:10px; background: rgba(0,0,0,0.2); padding:10px; }
    .proxy-item { padding:12px 15px; margin-bottom:8px; background: rgba(255,255,255,0.05); border-radius:8px; display:flex; justify-content:space-between; align-items:center; transition:all .2s ease; }
    .proxy-item:hover { background: rgba(255,255,255,0.1); }
    .proxy-active { border-left:4px solid var(--success); }
    .proxy-status { font-size:0.8rem; padding:4px 10px; border-radius:20px; font-weight:600; }
    .footer { text-align:center; margin-top:50px; padding:25px; opacity:0.7; font-size:0.9rem; border-top:1px solid rgba(255,255,255,0.1); }
    .credit { margin-top: 10px; font-size: 0.8rem; color: rgba(255,255,255,0.6); }
    .credit a { color: #00dbde; text-decoration: none; }
    .credit a:hover { text-decoration: underline; }
    .loading { display:inline-block; width:20px; height:20px; border:3px solid rgba(255,255,255,0.3); border-radius:50%; border-top-color:#fff; animation:spin 1s ease-in-out infinite; }
    @keyframes spin { to { transform: rotate(360deg); } }
    .notification { position: fixed; top:20px; right:20px; padding:15px 20px; background:var(--success); color:white; border-radius:10px; box-shadow:0 5px 15px rgba(0,0,0,0.2); transform: translateX(150%); transition: transform .3s ease; z-index:1000; }
    .notification.show { transform: translateX(0); }
    .progress-bar { height:6px; background: rgba(255,255,255,0.1); border-radius:3px; margin-top:10px; overflow:hidden; }
    .progress-fill { height:100%; background: linear-gradient(90deg,#00dbde,#fc00ff); border-radius:3px; width:0%; transition:width .3s ease; }
    @media (max-width:768px) { 
      .dashboard { grid-template-columns: 1fr; } 
      .header h1 { font-size:2.2rem; } 
      .actions { flex-direction:column; } 
      .btn { width:100%; justify-content:center; } 
      .clock-container { gap: 10px; } 
      .time-value { font-size: 1.1rem; } 
      .popup-title { font-size: 2rem; } 
      .popup-banner { padding: 20px; } 
      .running-text { font-size: 0.9rem; } 
      .running-text-item { margin: 0 15px; padding: 3px 10px; } 
      .wildcard-input-group { flex-direction: column; } 
      .wildcard-btn { width: 100%; }
      .visitor-info-container { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <!-- Popup Banner -->
  <div class="popup-overlay" id="popupBanner">
    <div class="popup-banner">
      <button class="popup-close" id="closePopup">&times;</button>
      <div class="popup-title">ANDRE CELL</div>
      <div class="popup-subtitle">PRESENTS</div>
      <div class="popup-content">
        <p>Welcome to ${decodedJudul} Worker - Premium Proxy Service</p>
        <p>Powered by advanced technology and secured connections</p>
        <p style="margin-top: 15px; color: #00dbde; font-weight: 600;">FEATURING:</p>
        <p>• Auto Bank Proxy Rotation<br>• Real-time Monitoring<br>• Secure UUID Generation<br>• High-Speed Connections</p>
      </div>
      <button class="sound-control" id="toggleSound">
        <i class="fas fa-volume-mute"></i> Toggle Background Sound
      </button>
    </div>
  </div>

  <div class="container">
    <div class="header">
      <h1><i class="fas fa-shield-alt"></i> ${decodedJudul} WORKER</h1>
      <p>Auto Bank Proxy System dengan UUID Otomatis dan Monitoring Real-time</p>
      
      <!-- Digital Clock -->
      <div class="digital-clock">
        <div class="clock-container">
          <div class="time-zone">
            <div class="time-label">WIB (Jakarta)</div>
            <div class="time-value" id="wib-time">00:00:00</div>
          </div>
          <div class="time-zone">
            <div class="time-label">WITA (Makassar)</div>
            <div class="time-value" id="wita-time">00:00:00</div>
          </div>
          <div class="time-zone">
            <div class="time-label">WIT (Jayapura)</div>
            <div class="time-value" id="wit-time">00:00:00</div>
          </div>
        </div>
      </div>
      
      <div style="margin-top:15px;">
        <span class="badge">Auto Proxy</span>
        <span class="badge">UUID Generator</span>
        <span class="badge">Real-time Ping</span>
        <span class="badge">Bank Proxy</span>
        <span class="badge">Traffic Monitor</span>
      </div>
    </div>

    <div class="dashboard">
      <div class="card">
        <div class="card-header">
          <i class="fas fa-sliders-h"></i>
          <h3>Konfigurasi Koneksi</h3>
        </div>

        <div class="info-grid">
          <div class="info-item">
            <span class="info-label"><i class="fas fa-fingerprint"></i> UUID:</span>
            <span class="info-value" id="uuid-value"><div class="loading"></div></span>
          </div>

          <div class="info-item">
            <span class="info-label"><i class="fas fa-server"></i> Server:</span>
            <span class="info-value" id="proxy-value"><div class="loading"></div></span>
          </div>

          <div class="info-item">
            <span class="info-label"><i class="fas fa-circle"></i> Status:</span>
            <span class="info-value">
              <span class="status-indicator status-active"></span>
              <span id="status-text">Active</span>
            </span>
          </div>
        </div>

        <!-- Wildcard Input Section -->
        <div class="wildcard-input-container">
          <div class="wildcard-input-group">
            <input type="text" class="wildcard-input" id="wildcard-input" placeholder="Masukkan wildcard bug (contoh: bug.com)" value="bug.com">
            <button class="wildcard-btn" id="apply-wildcard-btn">
              <i class="fas fa-check"></i> Apply
            </button>
          </div>
          <div class="wildcard-example">
            Contoh: bug.com, example.com, domain.local
          </div>
        </div>

        <div class="config-box" id="config-box">Menghasilkan konfigurasi...</div>
        <div class="progress-bar"><div class="progress-fill" id="config-progress"></div></div>

        <div class="actions">
          <button class="btn" id="refresh-btn"><i class="fas fa-sync-alt"></i> Refresh Config</button>
          <button class="btn btn-success" id="copy-btn"><i class="fas fa-copy"></i> Copy Config</button>
          <button class="btn btn-secondary" id="generate-vless-btn"><i class="fas fa-bolt"></i> Generate ${decodedFlash}</button>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <i class="fas fa-chart-line"></i>
          <h3>Status Koneksi</h3>
        </div>

        <div class="info-grid">
          <div class="info-item">
            <span class="info-label"><i class="fas fa-signal"></i> Ping Saat Ini:</span>
            <div class="ping-container">
              <span class="ping-value" id="ping-value">--</span>
              <span id="ping-status">ms</span>
            </div>
          </div>

          <div class="info-item">
            <span class="info-label"><i class="fas fa-clock"></i> Terakhir Diperiksa:</span>
            <span class="info-value" id="last-check">Never</span>
          </div>

          <div class="info-item">
            <span class="info-label"><i class="fas fa-stopwatch"></i> Uptime:</span>
            <span class="info-value" id="uptime-value">Calculating...</span>
          </div>
        </div>

        <div class="actions">
          <button class="btn" id="ping-btn"><i class="fas fa-satellite-dish"></i> Test Ping</button>
          <button class="btn btn-secondary" id="auto-ping-btn"><i class="fas fa-sync"></i> Auto Ping</button>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <i class="fas fa-network-wired"></i>
          <h3>Manajemen Proxy</h3>
        </div>

        <div class="info-grid">
          <div class="info-item">
            <span class="info-label"><i class="fas fa-shield-alt"></i> Proxy Aktif:</span>
            <span class="info-value" id="active-proxy"><div class="loading"></div></span>
          </div>

          <div class="info-item">
            <span class="info-label"><i class="fas fa-database"></i> Pool Proxy:</span>
            <span class="info-value" id="proxy-count"><div class="loading"></div></span>
          </div>
        </div>

        <div class="proxy-list" id="proxy-list">Memuat daftar proxy...</div>

        <div class="actions">
          <button class="btn" id="rotate-proxy-btn"><i class="fas fa-random"></i> Rotate Proxy</button>
          <button class="btn btn-secondary" id="refresh-proxies-btn"><i class="fas fa-redo"></i> Refresh Proxies</button>
        </div>
      </div>

      <!-- Visitor Information Card -->
      <div class="card">
        <div class="card-header">
          <i class="fas fa-users"></i>
          <h3>Informasi Pengunjung</h3>
        </div>

        <div class="visitor-info-container">
          <div class="visitor-card">
            <div class="visitor-header">
              <i class="fas fa-globe visitor-icon"></i>
              <div class="visitor-title">Informasi IP</div>
            </div>
            <div class="visitor-details">
              <div class="visitor-detail">
                <span class="visitor-label"><i class="fas fa-network-wired"></i> IP Address:</span>
                <span class="visitor-value ip-address" id="visitor-ip">Loading...</span>
              </div>
              <div class="visitor-detail">
                <span class="visitor-label"><i class="fas fa-map-marker-alt"></i> Lokasi:</span>
                <span class="visitor-value location-info" id="visitor-location">Loading...</span>
              </div>
              <div class="visitor-detail">
                <span class="visitor-label"><i class="fas fa-flag"></i> Negara:</span>
                <span class="visitor-value" id="visitor-country">Loading...</span>
              </div>
            </div>
          </div>

          <div class="visitor-card">
            <div class="visitor-header">
              <i class="fas fa-wifi visitor-icon"></i>
              <div class="visitor-title">Informasi ISP</div>
            </div>
            <div class="visitor-details">
              <div class="visitor-detail">
                <span class="visitor-label"><i class="fas fa-building"></i> Provider:</span>
                <span class="visitor-value isp-name" id="visitor-isp">Loading...</span>
              </div>
              <div class="visitor-detail">
                <span class="visitor-label"><i class="fas fa-satellite"></i> ASN:</span>
                <span class="visitor-value" id="visitor-asn">Loading...</span>
              </div>
              <div class="visitor-detail">
                <span class="visitor-label"><i class="fas fa-shield-alt"></i> Keamanan:</span>
                <span class="visitor-value" id="visitor-security">Loading...</span>
              </div>
            </div>
          </div>

          <div class="visitor-card">
            <div class="visitor-header">
              <i class="fas fa-info-circle visitor-icon"></i>
              <div class="visitor-title">Detail Sistem</div>
            </div>
            <div class="visitor-details">
              <div class="visitor-detail">
                <span class="visitor-label"><i class="fas fa-desktop"></i> Browser:</span>
                <span class="visitor-value" id="visitor-browser">Loading...</span>
              </div>
              <div class="visitor-detail">
                <span class="visitor-label"><i class="fas fa-mobile-alt"></i> Perangkat:</span>
                <span class="visitor-value" id="visitor-device">Loading...</span>
              </div>
              <div class="visitor-detail">
                <span class="visitor-label"><i class="fas fa-clock"></i> Waktu Akses:</span>
                <span class="visitor-value" id="visitor-time">Loading...</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Traffic Monitoring Card with Running Text -->
      <div class="card">
        <div class="card-header">
          <i class="fas fa-chart-bar"></i>
          <h3>Monitoring Trafik & Bandwidth</h3>
        </div>

        <div class="info-grid">
          <div class="info-item">
            <span class="info-label"><i class="fas fa-users"></i> Total Pengunjung:</span>
            <span class="info-value" id="total-visitors">0</span>
          </div>

          <div class="info-item">
            <span class="info-label"><i class="fas fa-user-clock"></i> Pengunjung Hari Ini:</span>
            <span class="info-value" id="today-visitors">0</span>
          </div>

          <div class="info-item">
            <span class="info-label"><i class="fas fa-database"></i> Total Bandwidth:</span>
            <span class="info-value" id="total-bandwidth">0 MB</span>
          </div>

          <div class="info-item">
            <span class="info-label"><i class="fas fa-bolt"></i> Bandwidth Hari Ini:</span>
            <span class="info-value" id="today-bandwidth">0 MB</span>
          </div>
        </div>

        <!-- Running Text Display -->
        <div class="running-text-container">
          <div class="running-text" id="running-text">
            <!-- Content akan diisi oleh JavaScript -->
          </div>
        </div>

        <!-- Mini Stats -->
        <div class="traffic-stats-mini">
          <div class="traffic-mini-item">
            <i class="fas fa-eye"></i> Views: <span class="traffic-mini-value" id="mini-total-visitors">0</span>
          </div>
          <div class="traffic-mini-item">
            <i class="fas fa-calendar-day"></i> Today: <span class="traffic-mini-value" id="mini-today-visitors">0</span>
          </div>
          <div class="traffic-mini-item">
            <i class="fas fa-network-wired"></i> Total BW: <span class="traffic-mini-value" id="mini-total-bandwidth">0MB</span>
          </div>
          <div class="traffic-mini-item">
            <i class="fas fa-tachometer-alt"></i> Today BW: <span class="traffic-mini-value" id="mini-today-bandwidth">0MB</span>
          </div>
        </div>

        <!-- Tombol Refresh Traffic dan Reset Data dihapus -->
      </div>
    </div>

    <div class="footer">
      <p>${decodedJudul} Worker • Auto Bank Proxy System • Real-time Monitoring</p>
      <div class="credit">
        <p>Dipersembahkan oleh <strong>ANDRE CELL</strong> | Powered by <a href="https://github.com/megawanted" target="_blank">@megawanted</a></p>
      </div>
      <p style="margin-top:10px; font-size:0.8rem;">System secara otomatis menghasilkan proxy bank dan UUID untuk koneksi yang aman</p>
    </div>
  </div>

  <div class="notification" id="notification"><span id="notification-text">Berhasil disalin!</span></div>

  <!-- Audio Element untuk Backsound -->
  <audio id="backgroundSound" loop>
    <source src="https://assets.mixkit.co/active_storage/sfx/251/251-preview.mp3" type="audio/mpeg">
    <source src="https://assets.mixkit.co/active_storage/sfx/251/251-preview.ogg" type="audio/ogg">
  </audio>

<script>
  // Backsound dan Popup Functions
  const backgroundSound = document.getElementById('backgroundSound');
  const popupBanner = document.getElementById('popupBanner');
  const closePopup = document.getElementById('closePopup');
  const toggleSound = document.getElementById('toggleSound');
  let isSoundPlaying = false;

  // Show popup on page load
  window.addEventListener('load', function() {
    setTimeout(() => {
      popupBanner.style.display = 'flex';
      // Auto play sound after 2 seconds
      setTimeout(() => {
        playScarySound();
      }, 2000);
    }, 1000);
  });

  // Close popup
  closePopup.addEventListener('click', function() {
    popupBanner.style.display = 'none';
  });

  // Toggle sound
  toggleSound.addEventListener('click', function() {
    if (isSoundPlaying) {
      backgroundSound.pause();
      toggleSound.innerHTML = '<i class="fas fa-volume-mute"></i> Play Background Sound';
    } else {
      playScarySound();
      toggleSound.innerHTML = '<i class="fas fa-volume-up"></i> Stop Background Sound';
    }
    isSoundPlaying = !isSoundPlaying;
  });

  function playScarySound() {
    backgroundSound.volume = 0.3;
    backgroundSound.play().catch(e => {
      console.log('Audio play failed:', e);
      // Fallback sound
      const fallbackSound = new Audio('data:audio/wav;base64,UklGRigAAABXQVZFZm10IBAAAAABAAEARKwAAIhYAQACABAAZGF0YQQAAAAAAA==');
      fallbackSound.volume = 0.2;
      fallbackSound.loop = true;
      fallbackSound.play();
    });
  }

  // Digital Clock Function
  function updateDigitalClock() {
    const now = new Date();
    
    // WIB (Jakarta) UTC+7
    const wibTime = new Date(now.getTime() + (7 * 60 * 60 * 1000));
    document.getElementById('wib-time').textContent = wibTime.toUTCString().split(' ')[4];
    
    // WITA (Makassar) UTC+8
    const witaTime = new Date(now.getTime() + (8 * 60 * 60 * 1000));
    document.getElementById('wita-time').textContent = witaTime.toUTCString().split(' ')[4];
    
    // WIT (Jayapura) UTC+9
    const witTime = new Date(now.getTime() + (9 * 60 * 60 * 1000));
    document.getElementById('wit-time').textContent = witTime.toUTCString().split(' ')[4];
  }

  // Update clock every second
  setInterval(updateDigitalClock, 1000);
  updateDigitalClock();

  // Visitor Information Functions
  async function loadVisitorInfo() {
    try {
      // Menggunakan API untuk mendapatkan informasi IP pengunjung
      const response = await fetch('https://ipapi.co/json/');
      const data = await response.json();
      
      // Update informasi pengunjung
      document.getElementById('visitor-ip').textContent = data.ip || 'Tidak diketahui';
      document.getElementById('visitor-location').textContent = (data.city || '') + ', ' + (data.region || '');
      document.getElementById('visitor-country').textContent = data.country_name || 'Tidak diketahui';
      document.getElementById('visitor-isp').textContent = data.org || data.asn || 'Tidak diketahui';
      document.getElementById('visitor-asn').textContent = data.asn || 'Tidak diketahui';
      
      // Deteksi browser dan perangkat
      detectBrowserAndDevice();
      
      // Update waktu akses
      document.getElementById('visitor-time').textContent = new Date().toLocaleString('id-ID');
      
      // Update informasi keamanan
      updateSecurityInfo(data);
      
    } catch (error) {
      console.error('Error loading visitor info:', error);
      // Fallback jika API tidak bekerja
      fallbackVisitorInfo();
    }
  }

  function detectBrowserAndDevice() {
    const userAgent = navigator.userAgent;
    let browser = 'Tidak diketahui';
    let device = 'Tidak diketahui';
    
    // Deteksi browser
    if (userAgent.includes('Chrome')) browser = 'Google Chrome';
    else if (userAgent.includes('Firefox')) browser = 'Mozilla Firefox';
    else if (userAgent.includes('Safari')) browser = 'Apple Safari';
    else if (userAgent.includes('Edge')) browser = 'Microsoft Edge';
    else if (userAgent.includes('Opera')) browser = 'Opera';
    
    // Deteksi perangkat
    if (userAgent.includes('Mobile')) device = 'Mobile/Tablet';
    else device = 'Desktop';
    
    document.getElementById('visitor-browser').textContent = browser;
    document.getElementById('visitor-device').textContent = device;
  }

  function updateSecurityInfo(data) {
    const security = navigator.userAgent.includes('HTTPS') ? 'Aman (HTTPS)' : 'Perhatian (HTTP)';
    document.getElementById('visitor-security').textContent = security;
    
    // Tambahkan warna berdasarkan keamanan
    const securityElement = document.getElementById('visitor-security');
    if (security.includes('Aman')) {
      securityElement.style.color = '#10b981';
    } else {
      securityElement.style.color = '#f59e0b';
    }
  }

  function fallbackVisitorInfo() {
    // Informasi fallback jika API tidak tersedia
    document.getElementById('visitor-ip').textContent = 'Tidak dapat mengambil IP';
    document.getElementById('visitor-location').textContent = 'Lokasi tidak tersedia';
    document.getElementById('visitor-country').textContent = 'Negara tidak diketahui';
    document.getElementById('visitor-isp').textContent = 'ISP tidak diketahui';
    document.getElementById('visitor-asn').textContent = 'ASN tidak diketahui';
    document.getElementById('visitor-security').textContent = 'Keamanan tidak diketahui';
    
    detectBrowserAndDevice();
    document.getElementById('visitor-time').textContent = new Date().toLocaleString('id-ID');
  }

  // Traffic Monitoring Functions
  async function loadTrafficStats() {
    try {
      const response = await fetch('/traffic');
      const data = await response.json();
      
      // Update UI dengan data traffic
      document.getElementById('total-visitors').textContent = data.totalVisitors.toLocaleString();
      document.getElementById('today-visitors').textContent = data.todayVisitors.toLocaleString();
      document.getElementById('total-bandwidth').textContent = data.totalBandwidth;
      document.getElementById('today-bandwidth').textContent = data.todayBandwidth;
      
      // Update mini stats
      document.getElementById('mini-total-visitors').textContent = data.totalVisitors.toLocaleString();
      document.getElementById('mini-today-visitors').textContent = data.todayVisitors.toLocaleString();
      document.getElementById('mini-total-bandwidth').textContent = data.totalBandwidth;
      document.getElementById('mini-today-bandwidth').textContent = data.todayBandwidth;
      
      // Update running text
      updateRunningText(data);
      
    } catch (error) {
      console.error('Error loading traffic stats:', error);
    }
  }

  // Fungsi untuk update running text
  function updateRunningText(data) {
    const runningText = document.getElementById('running-text');
    const judulDecoded = '${decodedJudul}';
    
    const messages = [
      '🚀 ' + judulDecoded + ' Worker - Total Pengunjung: ' + data.totalVisitors.toLocaleString() + ' orang',
      '📊 Pengunjung Hari Ini: ' + data.todayVisitors.toLocaleString() + ' orang',
      '💾 Total Bandwidth Digunakan: ' + data.totalBandwidth,
      '⚡ Bandwidth Hari Ini: ' + data.todayBandwidth,
      '🔒 Koneksi Aman - Powered by ANDRE CELL',
      '🌐 System Online - Real-time Monitoring Aktif',
      '🔄 Auto Proxy Rotation - Bank Proxy Terjamin',
      '📈 Traffic Monitoring - ' + data.todayVisitors + ' visitors today'
    ];

    // Buat elemen untuk setiap pesan
    runningText.innerHTML = '';
    messages.forEach((message, index) => {
      const span = document.createElement('span');
      span.className = 'running-text-item';
      span.textContent = message;
      runningText.appendChild(span);
      
      // Tambah pemisah kecuali untuk item terakhir
      if (index < messages.length - 1) {
        const separator = document.createElement('span');
        separator.innerHTML = ' • ';
        separator.style.color = '#fc00ff';
        separator.style.margin = '0 10px';
        runningText.appendChild(separator);
      }
    });
    
    // Duplicate content untuk efek seamless
    const clone = runningText.cloneNode(true);
    runningText.parentNode.appendChild(clone);
  }

  // Elements
  const uuidValue = document.getElementById('uuid-value');
  const proxyValue = document.getElementById('proxy-value');
  const configBox = document.getElementById('config-box');
  const configProgress = document.getElementById('config-progress');
  const pingValue = document.getElementById('ping-value');
  const pingStatus = document.getElementById('ping-status');
  const lastCheck = document.getElementById('last-check');
  const uptimeValue = document.getElementById('uptime-value');
  const statusText = document.getElementById('status-text');
  const activeProxy = document.getElementById('active-proxy');
  const proxyCount = document.getElementById('proxy-count');
  const proxyList = document.getElementById('proxy-list');
  const notification = document.getElementById('notification');
  const notificationText = document.getElementById('notification-text');
  const wildcardInput = document.getElementById('wildcard-input');
  const applyWildcardBtn = document.getElementById('apply-wildcard-btn');

  // Buttons
  const refreshBtn = document.getElementById('refresh-btn');
  const copyBtn = document.getElementById('copy-btn');
  const generateVlessBtn = document.getElementById('generate-vless-btn');
  const pingBtn = document.getElementById('ping-btn');
  const autoPingBtn = document.getElementById('auto-ping-btn');
  const rotateProxyBtn = document.getElementById('rotate-proxy-btn');
  const refreshProxiesBtn = document.getElementById('refresh-proxies-btn');

  // State
  let autoPingInterval = null;
  let startTime = Date.now();
  let currentConfig = null;
  let currentDomain = 'bug.com';

  function formatDuration(ms) {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    
    if (hours > 0) {
      return hours + "h " + (minutes % 60) + "m";
    } else if (minutes > 0) {
      return minutes + "m " + (seconds % 60) + "s";
    } else {
      return seconds + "s";
    }
  }

  function updateUptime() {
    uptimeValue.textContent = formatDuration(Date.now() - startTime);
  }

  function showNotification(message, type) {
    if (!type) type = 'success';
    notificationText.textContent = message;
    notification.className = 'notification show';
    notification.style.background = (type === 'error') ? 'var(--danger)' : 'var(--success)';
    setTimeout(function() { notification.classList.remove('show'); }, 3000);
  }

  // Load config dari backend dengan domain
  async function loadConfig(domain) {
    if (!domain) domain = currentDomain;
    try {
      configProgress.style.width = '30%';
      const domainParam = domain || currentDomain;
      const res = await fetch('/sub?domain=' + domainParam);
      const text = await res.text();
      configProgress.style.width = '70%';

      let data;
      try { data = JSON.parse(text); } catch(e) { data = { error: text }; }
      configProgress.style.width = '90%';

      if (data && !data.error) {
        uuidValue.textContent = data.uuid || 'n/a';
        proxyValue.textContent = data.ip + ':' + data.port + ' (' + (data.org || data.country || 'Unknown') + ')';

        activeProxy.textContent = proxyValue.textContent;

        // ambil string vless dari config_vls (hindari [object Object])
        if (data.config_vls && typeof data.config_vls === "object") {
          const firstKey = Object.keys(data.config_vls)[0];
          configBox.textContent = data.config_vls[firstKey];
          currentConfig = data.config_vls[firstKey];
        } else {
          configBox.textContent = data.config_vls || JSON.stringify(data, null, 2);
          currentConfig = configBox.textContent;
        }


        proxyCount.textContent = PROXY_SOURCE.length + ' proxies available';

        // tampilkan list proxy
        proxyList.innerHTML = '';
        
        PROXY_SOURCE.forEach(function(p) {
          const div = document.createElement('div');
          div.className = 'proxy-item proxy-inactive';
          div.innerHTML = '<span>' + p.prxIP + ':' + p.prxPort + ' - ' + (p.org || p.country || '') + '</span><span class="proxy-status">Inactive</span>';

          if (p.prxIP === data.ip && String(p.prxPort) === String(data.port)) {
            div.classList.remove('proxy-inactive');
            div.classList.add('proxy-active');
            div.querySelector('.proxy-status').textContent = 'Active';
          }
          proxyList.appendChild(div);
        });

        // test ping
        await testPing({ ip: data.ip, port: data.port });
      } else {
        configBox.textContent = 'No config (error)';
        showNotification('No config returned', 'error');
      }

      setTimeout(function() { configProgress.style.width = '0%'; }, 1000);
    } catch (err) {
      console.error(err);
      configBox.textContent = 'Error loading configuration';
      showNotification('Error loading configuration', 'error');
    }
  }

  // Apply wildcard bug
  function applyWildcard() {
    const domain = wildcardInput.value.trim();
    if (!domain) {
      showNotification('Masukkan domain wildcard!', 'error');
      return;
    }

    // Validasi domain sederhana
    if (!domain.includes('.') || domain.length < 3) {
      showNotification('Format domain tidak valid!', 'error');
      return;
    }

    currentDomain = domain;
    showNotification('Wildcard bug diterapkan: ' + domain, 'success');
    loadConfig(domain);
  }

  // Ping pakai /health
  async function testPing(proxy) {
    try {
      pingValue.textContent = '...';
      pingValue.className = 'ping-value';
      pingStatus.textContent = 'Testing...';

      if (!proxy || !proxy.ip) {
        pingValue.textContent = 'No IP';
        pingValue.className = 'ping-value ping-bad';
        pingStatus.textContent = 'No IP';
        return null;
      }

      const ipPort = proxy.ip + ':' + (proxy.port || '443');
      const res = await fetch('/health?ip=' + encodeURIComponent(ipPort));

      const data = await res.json();

      let latency = (data && typeof data.delay !== 'undefined') ? Number(data.delay) : null;
      if (latency !== null && !isNaN(latency)) {
        pingValue.textContent = latency;
        if (latency < 100) { 
          pingValue.className = 'ping-value ping-good'; 
          pingStatus.textContent = 'ms (Excellent)'; 
        } else if (latency < 300) { 
          pingValue.className = 'ping-value ping-medium'; 
          pingStatus.textContent = 'ms (Good)'; 
        } else { 
          pingValue.className = 'ping-value ping-bad'; 
          pingStatus.textContent = 'ms (Slow)'; 
        }
      } else {
        pingValue.textContent = 'N/A';
        pingValue.className = 'ping-value ping-bad';
        pingStatus.textContent = 'No delay';
      }

      lastCheck.textContent = new Date().toLocaleTimeString();
      statusText.textContent = 'Active';
      return latency;
    } catch (err) {
      console.error('Error testing ping:', err);
      pingValue.textContent = 'Error';
      pingValue.className = 'ping-value ping-bad';
      pingStatus.textContent = 'Connection failed';
      statusText.textContent = 'Error';
      return null;
    }
  }

  // Auto ping
  function toggleAutoPing() {
    if (autoPingInterval) {
      clearInterval(autoPingInterval);
      autoPingInterval = null;
      autoPingBtn.innerHTML = '<i class="fas fa-sync"></i> Auto Ping';
      autoPingBtn.classList.remove('btn-danger');
      showNotification('Auto ping stopped');
    } else {
      const parts = (activeProxy.textContent || '').split(':');
      const ip = parts[0];
      const port = parts[1] ? parts[1].split(' ')[0] : '443';
      testPing({ ip: ip, port: port });
      autoPingInterval = setInterval(function() { testPing({ ip: ip, port: port }); }, 5000);
      autoPingBtn.innerHTML = '<i class="fas fa-stop"></i> Stop Auto Ping';
      autoPingBtn.classList.add('btn-danger');
      showNotification('Auto ping started');
    }
  }

  // Copy config
  async function copyConfig() {
    if (!currentConfig) return showNotification('No configuration to copy', 'error');
    try {
      await navigator.clipboard.writeText(currentConfig);
      showNotification('Configuration copied to clipboard!');
    } catch (err) {
      showNotification('Error copying configuration', 'error');
    }
  }

  // Rotate proxy
  async function rotateProxy() {
    rotateProxyBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Rotating...';
    await loadConfig(currentDomain);
    showNotification('Proxy rotated successfully!');
    rotateProxyBtn.innerHTML = '<i class="fas fa-random"></i> Rotate Proxy';
  }

  // Refresh proxies
  async function refreshProxies() {
    refreshProxiesBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Refreshing...';
    await loadConfig(currentDomain);
    showNotification('Proxy list refreshed!');
    refreshProxiesBtn.innerHTML = '<i class="fas fa-redo"></i> Refresh Proxies';
  }

  // Event listeners
  refreshBtn.addEventListener('click', function() { loadConfig(currentDomain); });
  copyBtn.addEventListener('click', copyConfig);
  generateVlessBtn.addEventListener('click', function() { loadConfig(currentDomain); });
  pingBtn.addEventListener('click', function() {
    const parts = (activeProxy.textContent || '').split(':');
    const ip = parts[0];
    const port = parts[1] ? parts[1].split(' ')[0] : '443';
    testPing({ ip: ip, port: port });
  });
  autoPingBtn.addEventListener('click', toggleAutoPing);
  rotateProxyBtn.addEventListener('click', rotateProxy);
  refreshProxiesBtn.addEventListener('click', refreshProxies);
  applyWildcardBtn.addEventListener('click', applyWildcard);
  
  // Enter key untuk wildcard input
  wildcardInput.addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
      applyWildcard();
    }
  });

  // Initial load
  loadConfig(currentDomain);
  loadTrafficStats(); // Load traffic stats on page load
  loadVisitorInfo(); // Load visitor information on page load
  
  setTimeout(function() {
    const parts = (activeProxy.textContent || '').split(':');
    const ip = parts[0];
    const port = parts[1] ? parts[1].split(' ')[0] : '443';
    testPing({ ip: ip, port: port });
  }, 1000);

  setInterval(updateUptime, 1000);
  // Auto refresh traffic stats every 30 seconds
  setInterval(loadTrafficStats, 30000);
  // Auto refresh visitor info every 60 seconds
  setInterval(loadVisitorInfo, 60000);
</script>

</body>
</html>
`;
  return new Response(html, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-cache, no-store, must-revalidate"
    }
  });
}

/* =======================
   TRAFFIC STATS ENDPOINT
   ======================= */
async function serveTrafficStats(request) {
  const url = new URL(request.url);
  
  // Handle reset request
  if (url.searchParams.get('reset') === 'true' && request.method === 'POST') {
    trafficStats = {
      totalVisitors: 0,
      uniqueVisitors: new Set(),
      bandwidthUsed: 0,
      todayVisitors: 0,
      todayBandwidth: 0,
      lastReset: new Date().toISOString().split('T')[0]
    };
    
    return new Response(JSON.stringify({ 
      success: true, 
      message: 'Traffic data reset successfully' 
    }), {
      headers: { 
        "Content-Type": "application/json",
        ...CORS_HEADER_OPTIONS
      }
    });
  }
  
  // Return current traffic stats
  const stats = {
    totalVisitors: trafficStats.totalVisitors,
    todayVisitors: trafficStats.todayVisitors,
    totalBandwidth: formatBytes(trafficStats.bandwidthUsed),
    todayBandwidth: formatBytes(trafficStats.todayBandwidth),
    totalBandwidthValue: trafficStats.bandwidthUsed,
    todayBandwidthValue: trafficStats.todayBandwidth,
    lastReset: trafficStats.lastReset
  };
  
  return new Response(JSON.stringify(stats), {
    headers: { 
      "Content-Type": "application/json",
      ...CORS_HEADER_OPTIONS
    }
  });
}

/* =======================
   Simple /ping (used by UI)
   ======================= */
async function servePing() {
  // quick simulated ping response (UI measures roundtrip)
  return new Response(JSON.stringify({
    status: "ok",
    timestamp: Date.now(),
    message: "Ping test successful"
  }), {
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-cache",
      "Access-Control-Allow-Origin": "*"
    }
  });
}


/* =======================
   MAIN WORKER HANDLER
   ======================= */


import { connect } from "cloudflare:sockets";

/* =======================
   CONFIG
   ======================= */
const rootDomain = "mazlana.biz.id";
const serviceName = "cosmos";
const APP_DOMAIN = `${serviceName}.${rootDomain}`;
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

let cachedPrxList = {}; // cache per countryKey -> array

/* =======================
   UTIL: Fetch proxy list file and parse
   ======================= */
async function getPrxListByCountry(countryCode = "ALL") {
  const code = (countryCode || "ALL").toUpperCase();
  if (cachedPrxList[code]) return cachedPrxList[code];

  const url = `${PRX_BANK_BASE}/${code}.txt`;
  try {
    const res = await fetch(url);
    if (res.status !== 200) {
      // try fallback to ALL.txt
      if (code !== "ALL") {
        return getPrxListByCountry("ALL");
      }
      return [];
    }
    const text = await res.text();
    const lines = text.split("\n").map((l) => l.trim()).filter(Boolean);
    const parsed = lines.map((line) => {
      // expected: ip,port,CC,Org
      const parts = line.split(",").map((p) => p.trim());
      return {
        prxIP: parts[0] || "Unknown",
        prxPort: parts[1] || "443",
        country: parts[2] || code,
        org: parts[3] || "Unknown Org",
        raw: line,
      };
    });
    cachedPrxList[code] = parsed;
    return parsed;
  } catch (e) {
    return [];
  }
}

/* =======================
   HELPERS
   ======================= */
function shuffleArray(array) {
  let currentIndex = array.length;
  while (currentIndex !== 0) {
    const randomIndex = Math.floor(Math.random() * currentIndex);
    currentIndex--;
    [array[currentIndex], array[randomIndex]] = [
      array[randomIndex],
      array[currentIndex],
    ];
  }
  return array;
}

function arrayBufferToHex(buffer) {
  return [...new Uint8Array(buffer)]
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}

function base64ToArrayBuffer(base64Str) {
  if (!base64Str) return { error: null };
  try {
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const decode = atob(base64Str);
    const arr = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arr.buffer, error: null };
  } catch (error) {
    return { error };
  }
}

function safeCloseWebSocket(socket) {
  try {
    if (
      socket &&
      (socket.readyState === WS_READY_STATE_OPEN ||
        socket.readyState === WS_READY_STATE_CLOSING)
    ) {
      socket.close();
    }
  } catch (error) {
    console.error("safeCloseWebSocket error", error);
  }
}

/* =======================
   PROXY / SUB GENERATOR (ROTATE ONE RANDOM CONFIG from SG+ID with TLS & NTLS)
   ======================= */
async function generateSubscription(params) {
  const fillerDomain = params.domain || APP_DOMAIN;

  // Ambil list SG + ID
  const sgList = await getPrxListByCountry("SG");
  const idList = await getPrxListByCountry("ID");
  const prxList = [...sgList, ...idList];
  if (!prxList.length) return JSON.stringify({ error: "No proxy available" });

  // Ambil satu proxy random
  const prx = prxList[Math.floor(Math.random() * prxList.length)];
  const uuid = crypto.randomUUID();
 
   
   const config_vls = {
     [atob(flash)]: (() => {
     const uri = new URL(`${atob(flash)}://${fillerDomain}`);
     uri.searchParams.set("encryption", "none");
     uri.searchParams.set("type", "ws");
     uri.searchParams.set("host", APP_DOMAIN);
     uri.protocol = atob(flash);
     uri.port = "443";
     uri.username = uuid;
     uri.searchParams.set("security", "tls");
     uri.searchParams.set("sni", APP_DOMAIN);
     uri.searchParams.set("path", `/${prx.prxIP}-${prx.prxPort}`);
     uri.hash = `${prx.org} WS TLS [${serviceName}]`;
     return uri.toString();
     })()
     }



  const result = {
    uuid,
    ip: prx.prxIP,
    port: prx.prxPort,
    org: prx.org,
    config_vls
    
  };

  return JSON.stringify(result, null, 2);
}

/* =======================
   Reverse Web / Basic Proxy
   ======================= */
async function reverseWeb(request, target, targetPath) {
  const targetUrl = new URL(request.url);
  const targetChunk = (target || "example.com").split(":");

  targetUrl.hostname = targetChunk[0];
  targetUrl.port = targetChunk[1]?.toString() || "443";
  targetUrl.pathname = targetPath || targetUrl.pathname;

  const modifiedRequest = new Request(targetUrl, request);
  modifiedRequest.headers.set("X-Forwarded-Host", request.headers.get("Host") || "");
  const response = await fetch(modifiedRequest);
  const newResponse = new Response(response.body, response);
  for (const [key, value] of Object.entries(CORS_HEADER_OPTIONS)) {
    newResponse.headers.set(key, value);
  }
  newResponse.headers.set("X-Proxied-By", "Worker");
  return newResponse;
}

/* =======================
   WEBSOCKET HANDLER + TCP/UDP logic
   (ported and adapted from original code)
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
        async write(chunk) {
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
          } else {
            protocolHeader = readSsHeader(chunk);
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
              // UDP other than DNS is not supported in this worker
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
  // check uuid v4 pattern
  if (arrayBufferToHex(flashDelimiter).match(/^[0-9a-f]{8}[0-9a-f]{4}4[0-9a-f]{3}[89ab][0-9a-f]{3}[0-9a-f]{12}$/i)) {
    return atob(flash);
  }

  return "ss"; // default
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
    // TCP
  } else if (cmd === 2) {
    isDNS = true;
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
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 2:
      addressLength = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(buffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 3:
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
        message: `invalid  addressType is ${addressType}`,
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
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(dataBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 3:
      addressLength = new Uint8Array(dataBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(dataBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 4:
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
      (addressRemote || "").split(/[:=-]/)[0] || addressRemote,
      (addressRemote || "").split(/[:=-]/)[1] || portRemote
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


async function checkPrxHealth(prxIP, prxPort) {
  try {
    const req = await fetch(`${PRX_HEALTH_CHECK_API}?ip=${prxIP}:${prxPort}`);
    return await req.json();
  } catch (err) {
    return { error: 'fetch_failed', message: err.message };
  }
}



function serveUI() {
  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>${atob(judul)} Worker - Auto Bank Proxy</title>
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
    .loading { display:inline-block; width:20px; height:20px; border:3px solid rgba(255,255,255,0.3); border-radius:50%; border-top-color:#fff; animation:spin 1s ease-in-out infinite; }
    @keyframes spin { to { transform: rotate(360deg); } }
    .notification { position: fixed; top:20px; right:20px; padding:15px 20px; background:var(--success); color:white; border-radius:10px; box-shadow:0 5px 15px rgba(0,0,0,0.2); transform: translateX(150%); transition: transform .3s ease; z-index:1000; }
    .notification.show { transform: translateX(0); }
    .progress-bar { height:6px; background: rgba(255,255,255,0.1); border-radius:3px; margin-top:10px; overflow:hidden; }
    .progress-fill { height:100%; background: linear-gradient(90deg,#00dbde,#fc00ff); border-radius:3px; width:0%; transition:width .3s ease; }
    @media (max-width:768px) { .dashboard { grid-template-columns: 1fr; } .header h1 { font-size:2.2rem; } .actions { flex-direction:column; } .btn { width:100%; justify-content:center; } }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1><i class="fas fa-shield-alt"></i> ${atob(flash)} Worker</h1>
      <p>Auto Bank Proxy System dengan UUID Otomatis dan Monitoring Real-time</p>
      <div style="margin-top:15px;">
        <span class="badge">Auto Proxy</span>
        <span class="badge">UUID Generator</span>
        <span class="badge">Real-time Ping</span>
        <span class="badge">Bank Proxy</span>
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
            <span class="info-label"><i class="fas fa-server"></i> Proxy Server:</span>
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

        <div class="config-box" id="config-box">Menghasilkan konfigurasi...</div>
        <div class="progress-bar"><div class="progress-fill" id="config-progress"></div></div>

        <div class="actions">
          <button class="btn" id="refresh-btn"><i class="fas fa-sync-alt"></i> Refresh Config</button>
          <button class="btn btn-success" id="copy-btn"><i class="fas fa-copy"></i> Copy Config</button>
          <button class="btn btn-secondary" id="generate-vless-btn"><i class="fas fa-bolt"></i> Generate ${atob(flash)}</button>
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
    </div>

    <div class="footer">
      <p>${atob(flash)} Worker • Auto Bank Proxy System • Real-time Monitoring</p>
      <p style="margin-top:10px; font-size:0.8rem;">System secara otomatis menghasilkan proxy bank dan UUID untuk koneksi yang aman</p>
    </div>
  </div>

  <div class="notification" id="notification"><span id="notification-text">Berhasil disalin!</span></div>

<script>
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

  function formatDuration(ms) {
            const seconds = Math.floor(ms / 1000);
            const minutes = Math.floor(seconds / 60);
            const hours = Math.floor(minutes / 60);
            
            if (hours > 0) {
                return \`\${hours}h \${minutes % 60}m\`;
            } else if (minutes > 0) {
                return \`\${minutes}m \${seconds % 60}s\`;
            } else {
                return \`\${seconds}s\`;
            }
        }
  function updateUptime() {
    uptimeValue.textContent = formatDuration(Date.now() - startTime);
  }
  function showNotification(message, type='success') {
    notificationText.textContent = message;
    notification.className = 'notification show';
    notification.style.background = (type === 'error') ? 'var(--danger)' : 'var(--success)';
    setTimeout(()=> notification.classList.remove('show'), 3000);
  }

  // Load config dari backend
  async function loadConfig() {
    try {
      configProgress.style.width = '30%';
      const domain = location.hostname || '';
      const res = await fetch('/sub?domain=' + encodeURIComponent(domain));
      const text = await res.text();
      configProgress.style.width = '70%';

      let data;
      try { data = JSON.parse(text); } catch(e) { data = { error: text }; }
      configProgress.style.width = '90%';

      if (data && !data.error) {
        uuidValue.textContent = data.uuid || 'n/a';
        proxyValue.textContent = ${data.ip}:${data.port} (${data.org||''});
        activeProxy.textContent = proxyValue.textContent;

        configBox.textContent = data.config_vls || JSON.stringify(data, null, 2);
        currentConfig = configBox.textContent;

        // pool count dari SG + ID
        const [sgRes, idRes] = await Promise.all([fetch('/SG.txt'), fetch('/ID.txt')]);
        let sgList = [], idList = [];
        try { sgList = await sgRes.json(); } catch(e){}
        try { idList = await idRes.json(); } catch(e){}
        proxyCount.textContent = (sgList.length + idList.length) + ' proxies available';

        // tampilkan list proxy
        proxyList.innerHTML = '';
        [...sgList, ...idList].forEach(p => {
          const div = document.createElement('div');
          div.className = 'proxy-item proxy-inactive';
          div.innerHTML = '<span>${p.prxIP}:${p.prxPort} - ${p.org||p.country}</span><span class="proxy-status">Inactive</span>';
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

      setTimeout(()=> configProgress.style.width = '0%', 1000);
    } catch (err) {
      console.error(err);
      configBox.textContent = 'Error loading configuration';
      showNotification('Error loading configuration', 'error');
    }
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
      const res = await fetch('/health?ip=${encodeURIComponent(ipPort)}');
      const data = await res.json();

      let latency = (data && typeof data.delay !== 'undefined') ? Number(data.delay) : null;
      if (latency !== null && !isNaN(latency)) {
        pingValue.textContent = latency;
        if (latency < 100) { pingValue.className = 'ping-value ping-good'; pingStatus.textContent = 'ms (Excellent)'; }
        else if (latency < 300) { pingValue.className = 'ping-value ping-medium'; pingStatus.textContent = 'ms (Good)'; }
        else { pingValue.className = 'ping-value ping-bad'; pingStatus.textContent = 'ms (Slow)'; }
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
      const port = parts[1] ? parts[1].split(' ')[0] : '443'; // buang "(ORG)" setelah port
      testPing({ ip, port });
      autoPingInterval = setInterval(() => testPing({ ip, port }), 5000);
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
    await loadConfig();
    showNotification('Proxy rotated successfully!');
    rotateProxyBtn.innerHTML = '<i class="fas fa-random"></i> Rotate Proxy';
  }

  // Refresh proxies
  async function refreshProxies() {
    refreshProxiesBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Refreshing...';
    await loadConfig();
    showNotification('Proxy list refreshed!');
    refreshProxiesBtn.innerHTML = '<i class="fas fa-redo"></i> Refresh Proxies';
  }

  // Event listeners
  refreshBtn.addEventListener('click', loadConfig);
  copyBtn.addEventListener('click', copyConfig);
  generateVlessBtn.addEventListener('click', loadConfig);
  pingBtn.addEventListener('click', () => {
    const parts = (activeProxy.textContent || '').split(':');
    const ip = parts[0];
    const port = parts[1] ? parts[1].split(' ')[0] : '443';
    testPing({ ip, port });
  });
  autoPingBtn.addEventListener('click', toggleAutoPing);
  rotateProxyBtn.addEventListener('click', rotateProxy);
  refreshProxiesBtn.addEventListener('click', refreshProxies);

  // Initial load
  loadConfig();
  setTimeout(() => {
    const parts = (activeProxy.textContent || '').split(':');
    const ip = parts[0];
    const port = parts[1] ? parts[1].split(' ')[0] : '443';
    testPing({ ip, port });
  }, 1000);

  setInterval(updateUptime, 1000);
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
   Expose SG and ID raw lists (parsed JSON)
   ======================= */
async function servePrxList(country) {
  const list = await getPrxListByCountry(country);
  return new Response(JSON.stringify(list, null, 2), {
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
export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const pathname = url.pathname;
      const upgradeHeader = request.headers.get("Upgrade");

      // CORS preflight
      if (request.method === "OPTIONS") {
        return new Response(null, { status: 204, headers: CORS_HEADER_OPTIONS });
      }

      // Root -> UI (exact UI from worker 4)
      if (pathname === "/") {
        return serveUI();
      }
      
      // route: /health?ip=1.2.3.4&port=443
// === Route: /health?ip=IP:PORT ===
if (pathname === "/health") {
  const ipPort = url.searchParams.get("ip"); // contoh: "138.2.89.64:32962"
  if (!ipPort) {
    return new Response(JSON.stringify({ error: "missing_ip" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  // pisahkan jadi ip dan port
  const [ip, port] = ipPort.split(":");

  const result = await checkPrxHealth(ip, port || "443");
  return new Response(JSON.stringify(result, null, 2), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}





      // Expose SG/ID lists for UI
      if (pathname === "/SG.txt") {
        return await servePrxList("SG");
      }
      if (pathname === "/ID.txt") {
        return await servePrxList("ID");
      }

      // /sub -> single rotated config from SG+ID (accept ?domain=...)
      if (pathname.startsWith("/sub")) {
        const params = Object.fromEntries(url.searchParams.entries());
        const out = await generateSubscription(params);
        return new Response(out, {
          status: 200,
          headers: { "Content-Type": "application/json; charset=utf-8", ...CORS_HEADER_OPTIONS },
        });
      }

      // /ping used by UI
      if (pathname === "/ping") {
        return servePing();
      }

      // WebSocket upgrade handler (proxying TCP/UDP via sockets)
      if (upgradeHeader === "websocket") {
        return await websocketHandler(request);
      }

      // Default: simple reverse proxy
      const targetReversePrx = (env && env.REVERSE_PRX_TARGET) || "example.com";
      return await reverseWeb(request, targetReversePrx);

    } catch (err) {
      return new Response(`An error occurred: ${err.toString()}`, {
        status: 500,
        headers: { ...CORS_HEADER_OPTIONS },
      });
    }
  },
};

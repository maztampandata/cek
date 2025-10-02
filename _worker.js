

import { connect } from "cloudflare:sockets";

/* =======================
   CONFIG
   ======================= */
const rootDomain = "mazlana.biz.id"; // replace if needed
const serviceName = "cosmos";
const APP_DOMAIN = `${serviceName}.${rootDomain}`;

const horse = "dHJvamFu"; // base64 marker (trojan)
const flash = "dmxlc3M="; // base64 marker (vmess)
const v2 = "djJyYXk="; // base64 v2ray
const neko = "Y2xhc2g="; // base64 clash

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
   PROXY / SUB GENERATOR
   ======================= */
async function generateSubscription(params) {
  // params: cc (comma list), port, vpn (comma), limit, format, domain
  const filterCC = (params.cc || "ALL").split(",").map((s) => s.trim().toUpperCase());
  const filterPort = (params.port || PORTS.join(",")).split(",").map((s) => s.trim());
  const filterVPN = (params.vpn || PROTOCOLS.join(","))
    .split(",")
    .map((s) => s.trim());
  const filterLimit = parseInt(params.limit || "1000", 10) || 1000;
  const filterFormat = params.format || "raw";
  const fillerDomain = params.domain || APP_DOMAIN;
  const prxListParam = params["prx-list"]; // optional custom raw list URL

  // get list
  let prxList = [];
  if (prxListParam) {
    try {
      const res = await fetch(prxListParam);
      if (res.status === 200) {
        const text = await res.text();
        prxList = text.split("\n").filter(Boolean).map((line) => {
          const [ip, port, cc, org] = line.split(",").map((s) => s.trim());
          return { prxIP: ip, prxPort: port || "443", country: cc || "ALL", org: org || "Unknown" };
        });
      }
    } catch (e) {
      prxList = [];
    }
  } else {
    // If user asks multiple CCs, prioritize those; else ALL
    if (filterCC.length === 1 && filterCC[0] !== "ALL") {
      prxList = await getPrxListByCountry(filterCC[0]);
    } else {
      // merge lists for requested CCs
      if (filterCC.includes("ALL")) {
        prxList = await getPrxListByCountry("ALL");
      } else {
        // fetch per requested cc and flatten
        const arrs = await Promise.all(filterCC.map((cc) => getPrxListByCountry(cc)));
        prxList = arrs.flat();
      }
    }
  }

  if (!prxList || prxList.length === 0) return [];

  // filter by country if filterCC explicitly provided
  if (filterCC.length && !filterCC.includes("ALL")) {
    prxList = prxList.filter((p) => filterCC.includes((p.country || "").toUpperCase()));
  }

  shuffleArray(prxList);

  const uuid = crypto.randomUUID();
  const result = [];
  for (const prx of prxList) {
    for (const port of filterPort) {
      for (const protocol of filterVPN) {
        if (result.length >= filterLimit) break;

        try {
          const uri = new URL(`${atob(horse)}://${fillerDomain}`);
          uri.searchParams.set("encryption", "none");
          uri.searchParams.set("type", "ws");
          uri.searchParams.set("host", APP_DOMAIN);

          uri.protocol = protocol;
          uri.port = port.toString();
          if (protocol === "ss") {
            uri.username = btoa(`none:${uuid}`);
            uri.searchParams.set(
              "plugin",
              `${atob(v2)}-plugin${port == 80 ? "" : ";tls"};mux=0;mode=websocket;path=/${prx.prxIP}-${prx.prxPort};host=${APP_DOMAIN}`
            );
          } else {
            uri.username = uuid;
            uri.searchParams.delete("plugin");
          }

          uri.searchParams.set("security", port == 443 ? "tls" : "none");
          uri.searchParams.set("sni", port == 80 && protocol === atob(flash) ? "" : APP_DOMAIN);
          uri.searchParams.set("path", `/${prx.prxIP}-${prx.prxPort}`);
          uri.hash = `${result.length + 1} ${prx.org} WS ${port == 443 ? "TLS" : "NTLS"} [${serviceName}]`;

          result.push(uri.toString());
        } catch (e) {
          // skip bad entries
        }
      }
      if (result.length >= filterLimit) break;
    }
    if (result.length >= filterLimit) break;
  }

  // Build formattedResult (useful structured version)
  const formattedResult = prxList.slice(0, filterLimit).map((prx, idx) => {
    const config_tls = {
      [atob(horse)]: (() => {
        const uri = new URL(`${atob(horse)}://${fillerDomain}`);
        uri.searchParams.set("encryption", "none");
        uri.searchParams.set("type", "ws");
        uri.searchParams.set("host", APP_DOMAIN);
        uri.protocol = atob(horse);
        uri.port = "443";
        uri.username = uuid;
        uri.searchParams.set("security", "tls");
        uri.searchParams.set("sni", APP_DOMAIN);
        uri.searchParams.set("path", `/${prx.prxIP}-${prx.prxPort}`);
        uri.hash = `${prx.org} WS TLS [${serviceName}]`;
        return uri.toString();
      })(),
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
      })(),
      ss: (() => {
        const uri = new URL(`ss://${fillerDomain}`);
        uri.searchParams.set("encryption", "none");
        uri.searchParams.set("type", "ws");
        uri.searchParams.set("host", APP_DOMAIN);
        uri.protocol = "ss";
        uri.port = "443";
        uri.username = btoa(`none:${uuid}`);
        uri.searchParams.set("security", "tls");
        uri.searchParams.set("sni", APP_DOMAIN);
        uri.searchParams.set("path", `/${prx.prxIP}-${prx.prxPort}`);
        uri.searchParams.set(
          "plugin",
          `${atob(v2)}-plugin;tls;mux=0;mode=websocket;path=/${prx.prxIP}-${prx.prxPort};host=${APP_DOMAIN}`
        );
        uri.hash = `${prx.org} WS TLS [${serviceName}]`;
        return uri.toString();
      })(),
    };

    const config_ntls = {
      [atob(horse)]: (() => {
        const uri = new URL(`${atob(horse)}://${fillerDomain}`);
        uri.searchParams.set("encryption", "none");
        uri.searchParams.set("type", "ws");
        uri.searchParams.set("host", APP_DOMAIN);
        uri.protocol = atob(horse);
        uri.port = "80";
        uri.username = uuid;
        uri.searchParams.set("security", "none");
        uri.searchParams.set("sni", "");
        uri.searchParams.set("path", `/${prx.prxIP}-${prx.prxPort}`);
        uri.hash = `${prx.org} WS NTLS [${serviceName}]`;
        return uri.toString();
      })(),
      [atob(flash)]: (() => {
        const uri = new URL(`${atob(flash)}://${fillerDomain}`);
        uri.searchParams.set("encryption", "none");
        uri.searchParams.set("type", "ws");
        uri.searchParams.set("host", APP_DOMAIN);
        uri.protocol = atob(flash);
        uri.port = "80";
        uri.username = uuid;
        uri.searchParams.set("security", "none");
        uri.searchParams.set("sni", "");
        uri.searchParams.set("path", `/${prx.prxIP}-${prx.prxPort}`);
        uri.hash = `${prx.org} WS NTLS [${serviceName}]`;
        return uri.toString();
      })(),
      ss: (() => {
        const uri = new URL(`ss://${fillerDomain}`);
        uri.searchParams.set("encryption", "none");
        uri.searchParams.set("type", "ws");
        uri.searchParams.set("host", APP_DOMAIN);
        uri.protocol = "ss";
        uri.port = "80";
        uri.username = btoa(`none:${uuid}`);
        uri.searchParams.set("security", "none");
        uri.searchParams.set("sni", "");
        uri.searchParams.set("path", `/${prx.prxIP}-${prx.prxPort}`);
        uri.searchParams.set(
          "plugin",
          `${atob(v2)}-plugin;mux=0;mode=websocket;path=/${prx.prxIP}-${prx.prxPort};host=${APP_DOMAIN}`
        );
        uri.hash = `${prx.org} WS NTLS [${serviceName}]`;
        return uri.toString();
      })(),
    };

    return {
      ip: prx.prxIP,
      port: prx.prxPort,
      orgz: prx.org,
      config_tls,
      config_ntls,
      idx,
    };
  });

  // Now produce finalResult based on requested format
  let finalResult = "";
  

  return finalResult;
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

      // Proxy files: /SG.txt, /ID.txt, /ALL.txt
      if (pathname === "/SG.txt") {
        const list = await getPrxListByCountry("SG");
        return new Response(JSON.stringify(list, null, 2), {
          status: 200,
          headers: { "Content-Type": "application/json", ...CORS_HEADER_OPTIONS },
        });
      }
      if (pathname === "/ID.txt") {
        const list = await getPrxListByCountry("ID");
        return new Response(JSON.stringify(list, null, 2), {
          status: 200,
          headers: { "Content-Type": "application/json", ...CORS_HEADER_OPTIONS },
        });
      }
      // /check?target=1.2.3.4:443  -> health check via external health API
      if (pathname === "/check") {
        const target = url.searchParams.get("target") || "";
        const [ip, port] = target.split(":");
        if (!ip) {
          return new Response("Missing target", { status: 400 });
        }
        const res = await checkPrxHealth(ip, port || "443");
        return new Response(JSON.stringify(res, null, 2), {
          status: 200,
          headers: { "Content-Type": "application/json", ...CORS_HEADER_OPTIONS },
        });
      }

      // /sub -> generate subscription/config list
      
      // WebSocket upgrade handler (proxying TCP/UDP via sockets)
      if (upgradeHeader === "websocket") {
        return await websocketHandler(request);
      }

      // Otherwise, act as a simple reverse proxy to REVERSE_PRX_TARGET env or example.com
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

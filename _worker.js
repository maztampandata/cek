// WebSocket
if (upgradeHeader === "websocket") {
  const prxMatch = url.pathname.match(/^\/(.+[:=-]\d+)$/);

  // Default: ambil random proxy dari SG+ID
  let selectedPrx = null;
  const allList = [...await getPrxListByCountry("SG"), ...await getPrxListByCountry("ID")];

  if (prxMatch) {
    // kalau path berisi IP:PORT, pakai itu
    selectedPrx = { prxIP: prxMatch[1].split(/[:=-]/)[0], prxPort: prxMatch[1].split(/[:=-]/)[1] || "443" };
  } else if (allList.length) {
    // fallback random
    selectedPrx = allList[Math.floor(Math.random() * allList.length)];
  }

  if (!selectedPrx) {
    return new Response("No proxy available", { status: 503 });
  }

  // Bisa diteruskan ke handler
  request.selectedPrx = selectedPrx;
  return await websocketHandler(request);
}

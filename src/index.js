import { connect } from 'cloudflare:sockets';

export default {
  async fetch(req) {
    const url = new URL(req.url);
    const rawTarget = url.searchParams.get("target");

    // Camuflaje si visitan directo sin ?target
    if (req.method === "GET" && !rawTarget) {
      return new Response("", {
        status: 204,
        headers: {
          "Content-Type": "font/woff2",
          "Access-Control-Allow-Origin": "*",
          "X-Cache": "MISS",
        },
      });
    }

    // Validación y parsing del target
    const [hostname, portStr] = rawTarget.split(":");
    const port = parseInt(portStr, 10);
    if (!hostname || !port) {
      return new Response("Invalid target", { status: 400 });
    }

    try {
      const socket = connect({ hostname, port });

      // Manejo WebSocket
      if (req.headers.get("Upgrade")?.toLowerCase() === "websocket") {
        const { 0: client, 1: server } = new WebSocketPair();

        // Flujo WebSocket <-> TCP socket
        socket.readable.pipeTo(server.writable).catch(() => {});
        server.readable.pipeTo(socket.writable).catch(() => {});

        return new Response(null, { status: 101, webSocket: client });
      }

      return new Response("Expected WebSocket upgrade", { status: 400 });
    } catch (err) {
      return new Response("Connect error: " + err.message, { status: 502 });
    }
  },
};

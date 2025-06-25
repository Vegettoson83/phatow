import { connect } from 'cloudflare:sockets';

export default {
  async fetch(req) {
    const url = new URL(req.url);
    const target = url.searchParams.get("target");

    if (req.method === "GET" && !url.searchParams.has("target")) {
      return new Response("", {
        status: 204,
        headers: {
          "Content-Type": "font/woff2",
          "Access-Control-Allow-Origin": "*",
          "X-Cache": "MISS",
        },
      });
    }

    try {
      const socket = connect({ hostname: target.split(':')[0], port: parseInt(target.split(':')[1]) });

      const upgrade = req.headers.get("Upgrade") || "";

      if (upgrade.toLowerCase() === "websocket") {
        const pair = new WebSocketPair();
        const [client, server] = [pair[0], pair[1]];

        socket.readable.pipeTo(server.writable).catch(() => {});
        server.readable.pipeTo(socket.writable).catch(() => {});

        return new Response(null, { status: 101, webSocket: client });
      }

      return new Response("Expected WebSocket", { status: 400 });
    } catch (err) {
      return new Response("Connect error: " + err, { status: 502 });
    }
  },
};

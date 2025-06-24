// orchestrator/cloudflare/worker.js
import { connect } from 'cloudflare:sockets';
// Nota: 'cloudflare:crypto' para hmac no es la forma estándar.
// La API Web Crypto (crypto.subtle) es la forma correcta y está disponible en Cloudflare Workers.
// Asumiré que la intención era usar la API Web Crypto.

async function verifyHmac(secretKeyText, signatureHex, dataText) {
  try {
    const keyBytes = new TextEncoder().encode(secretKeyText); // El secreto debe ser conocido
    const signatureBytes = Uint8Array.from(signatureHex.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
    const dataBytes = new TextEncoder().encode(dataText);

    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );

    return await crypto.subtle.verify(
      "HMAC",
      cryptoKey,
      signatureBytes,
      dataBytes
    );
  } catch (e) {
    console.error("Error verifying HMAC:", e.message);
    return false;
  }
}


export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === '/health') {
      return new Response('🔥 PHANTOM GATEWAY WORKER OPERATIONAL 🔥', { status: 200 });
    }

    const upgradeHeader = request.headers.get('Upgrade');
    if (upgradeHeader && upgradeHeader.toLowerCase() === 'websocket') {
      return this.handleWebSocket(request, env);
    }

    return new Response('Expected WebSocket upgrade or /health endpoint.', { status: 400 });
  },

  async handleWebSocket(request, env) {
    const authHeader = request.headers.get('X-Phantom-Auth');
    if (!authHeader) {
      return new Response('Missing X-Phantom-Auth header', { status: 401 });
    }

    const parts = authHeader.split('.');
    if (parts.length !== 2) {
      return new Response('Invalid X-Phantom-Auth format', { status: 401 });
    }
    const [timestampStr, signatureHex] = parts;
    const timestamp = parseInt(timestampStr, 10);

    if (isNaN(timestamp) || Date.now() - timestamp > 5000) { // 5-second window
      return new Response('Authentication timestamp expired or invalid', { status: 401 });
    }

    // AUTH_SECRET se espera que esté configurado en las variables de entorno del Worker (secrets)
    if (!env.AUTH_SECRET) {
      console.error("AUTH_SECRET is not configured in Worker environment.");
      return new Response('Server authentication error', { status: 500 });
    }

    const isValid = await verifyHmac(env.AUTH_SECRET, signatureHex, timestampStr);

    if (!isValid) {
      return new Response('Invalid authentication signature', { status: 401 });
    }

    const [clientWebSocket, serverWebSocket] = Object.values(new WebSocketPair());
    serverWebSocket.accept();

    // El cliente enviará un mensaje 'connect' con host y puerto después de establecer el WebSocket
    serverWebSocket.addEventListener('message', async (event) => {
      try {
        const message = JSON.parse(event.data);

        if (message.type === 'connect' && message.host && message.port) {
          if (!env.TUNNEL_HOST || !env.TUNNEL_PORT) {
            console.error("TUNNEL_HOST or TUNNEL_PORT is not configured in Worker environment.");
            serverWebSocket.send(JSON.stringify({ type: 'error', message: 'Tunnel misconfiguration on server.' }));
            serverWebSocket.close(1011, "Server tunnel misconfiguration");
            return;
          }

          const tunnelSocket = connect({
            hostname: env.TUNNEL_HOST, // Este es el hostname del servicio cloudflared expone
            port: parseInt(env.TUNNEL_PORT, 10), // Puerto del servicio cloudflared
            // servername: env.TUNNEL_HOST // SNI, usualmente el mismo que hostname
          });

          const writer = tunnelSocket.writable.getWriter();
          // El backend espera "host:port\n" como la primera línea para saber a dónde conectarse.
          await writer.write(
            new TextEncoder().encode(`${message.host}:${message.port}\n`)
          );
          writer.releaseLock(); // Importante liberar el lock después de escribir

          this.setupBidirectionalForwarding(serverWebSocket, tunnelSocket, message.sessionId || "N/A");

        } else if (message.type === 'data' && message.sessionId) {
          // Este es el flujo de datos del cliente al túnel
          // Este manejo se mueve a setupBidirectionalForwarding
        } else {
          console.log("Received unhandled message type or format:", message.type);
          // serverWebSocket.send(JSON.stringify({ type: 'error', message: 'Unhandled message type' }));
        }
      } catch (err) {
        console.error('Error handling client message:', err.stack);
        serverWebSocket.send(JSON.stringify({ type: 'error', message: 'Error processing your request.' }));
        // No cerrar el WebSocket aquí a menos que sea un error irrecuperable.
      }
    });

    serverWebSocket.addEventListener('close', event => {
      console.log(`Server WebSocket closed: code ${event.code}, reason: ${event.reason}`);
    });
    serverWebSocket.addEventListener('error', error => {
      console.error('Server WebSocket error:', error.message || error);
    });

    return new Response(null, { status: 101, webSocket: clientWebSocket });
  },

  setupBidirectionalForwarding(clientWs, tunnelSocket, sessionId) {
    let tunnelWriter = null;
    try {
        tunnelWriter = tunnelSocket.writable.getWriter();
    } catch (e) {
        console.error(`[${sessionId}] Failed to get tunnel writer:`, e);
        clientWs.close(1011, "Tunnel connection error");
        return;
    }

    // Cliente WebSocket → Tunnel
    const clientWsListener = async (event) => {
      try {
        const message = JSON.parse(event.data); // Asumimos que el cliente siempre envía JSON
        if (message.type === 'data' && message.data) {
          // Los datos ya vienen del cliente como base64, el backend los decodifica.
          // Aquí, el worker recibe datos del cliente (ya en base64) y los pasa al túnel.
          // El backend espera datos binarios después de la línea inicial "host:port\n".
          // El cliente SOCKS5 envía datos binarios, que el phantom-client codifica a base64.
          // El worker recibe ese base64 y debe decodificarlo antes de enviarlo al túnel/backend.
          const binaryData = Uint8Array.from(atob(message.data), c => c.charCodeAt(0));
          await tunnelWriter.write(binaryData);
        } else if (message.type === 'close') {
           console.log(`[${sessionId}] Client requested close for session.`);
           await tunnelWriter.close();
           clientWs.close(1000, "Client closed session");
        }
      } catch (err) {
        console.error(`[${sessionId}] Error forwarding data from client to tunnel:`, err.stack);
        // Considerar cerrar la conexión si hay error grave
        // clientWs.close(1011, "Forwarding error");
        // tunnelSocket.close(); // O abortar el túnel
      }
    };
    clientWs.addEventListener('message', clientWsListener);

    // Tunnel → Cliente WebSocket
    const processTunnelData = async () => {
      let tunnelReader;
      try {
        tunnelReader = tunnelSocket.readable.getReader();
      } catch (e) {
        console.error(`[${sessionId}] Failed to get tunnel reader:`, e);
        clientWs.close(1011, "Tunnel connection error");
        return;
      }

      try {
        while (true) {
          const { value, done } = await tunnelReader.read();
          if (done) {
            console.log(`[${sessionId}] Tunnel stream ended. Closing client WebSocket.`);
            clientWs.send(JSON.stringify({ type: 'close', sessionId })); // Notificar al cliente
            clientWs.close(1000, 'Tunnel closed');
            break;
          }
          // Los datos del túnel son binarios. Deben ser codificados a base64 para enviar por WebSocket.
          let base64Data = btoa(String.fromCharCode.apply(null, value));
          clientWs.send(JSON.stringify({
            type: 'data',
            sessionId, // El cliente podría necesitar esto si maneja múltiples túneles por un WS (no es el caso aquí)
            data: base64Data
          }));
        }
      } catch (err) {
        console.error(`[${sessionId}] Error reading from tunnel or sending to client:`, err.stack);
        clientWs.close(1011, 'Tunnel read/forward error');
      } finally {
        tunnelReader.releaseLock();
      }
    };

    processTunnelData().catch(e => {
        console.error(`[${sessionId}] Uncaught error in processTunnelData:`, e);
        clientWs.close(1011, 'Tunnel processing error');
    });

    // Manejar cierre desde el cliente
    clientWs.addEventListener('close', async (event) => {
      console.log(`[${sessionId}] Client WebSocket closed (code: ${event.code}, reason: ${event.reason}). Cleaning up tunnel.`);
      clientWs.removeEventListener('message', clientWsListener); // Limpiar listener
      if (tunnelWriter) {
        try {
          await tunnelWriter.close();
        } catch (e) {
          // Puede fallar si ya está cerrado, ignorar.
        }
      }
      // tunnelSocket.close(); // Opcional, dependiendo de si 'writer.close()' lo maneja.
    });
  }
};

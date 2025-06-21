import { connect } from 'cloudflare:sockets';
// AES_GCM is not directly available from 'cloudflare:crypto'
// Instead, use crypto.subtle for AES-GCM operations.
// import { AES_GCM } from 'cloudflare:crypto';

export default {
  async fetch(request, env, ctx) {
    const upgradeHeader = request.headers.get('Upgrade');
    if (upgradeHeader === 'websocket') {
      return this.handleWebSocket(request, env, ctx); // Added ctx
    }

    const url = new URL(request.url);
    if (request.method === 'POST' && url.pathname === '/session') {
      return this.handleSessionInit(request, env);
    }

    return new Response('Phantom Gateway 2.1', { status: 200 });
  },

  async handleSessionInit(request, env) {
    const { host, port, salt } = await request.json();
    const sessionId = crypto.randomUUID();

    // Almacenamiento efímero (15 minutos)
    await env.KV_SESSIONS.put(sessionId, JSON.stringify({ host, port, salt }), {
      expirationTtl: 900
    });

    return new Response(JSON.stringify({ sessionId }), {
      headers: { 'Content-Type': 'application/json' }
    });
  },

  async handleWebSocket(request, env, ctx) { // Added ctx
    const [client, server] = Object.values(new WebSocketPair());
    server.accept();

    server.addEventListener('message', async (event) => {
      try {
        const data = JSON.parse(event.data);

        if (data.type === 'init') {
          const sessionData = await env.KV_SESSIONS.get(data.sessionId, 'json');
          if (!sessionData) {
            server.send(JSON.stringify({ error: 'Invalid session' }));
            server.close(1008);
            return;
          }

          // Deriva clave usando HKDF
          const hkdf = await crypto.subtle.importKey(
            'raw',
            base64ToArrayBuffer(data.clientKey),
            { name: 'HKDF' },
            false,
            ['deriveKey']
          );

          const derivedKey = await crypto.subtle.deriveKey(
            {
              name: 'HKDF',
              salt: base64ToArrayBuffer(sessionData.salt),
              info: new TextEncoder().encode('phantom-gateway-key'),
              hash: 'SHA-256'
            },
            hkdf,
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
          );

          // Conexión persistente al destino
          const socket = connect({ // `connect` is part of 'cloudflare:sockets'
            hostname: sessionData.host,
            port: sessionData.port
          });

          const socketReader = socket.readable.getReader();
          const socketWriter = socket.writable.getWriter();

          // Comunicación bidireccional
          ctx.waitUntil(this.handleBidirectional(
            server,
            socketReader,
            socketWriter,
            derivedKey,
            websocket // Pass websocket to handleBidirectional
          ));
        }
      } catch (e) {
        // console.error("WebSocket init error:", e); // Optional: log the error
        server.close(1011);
      }
    });

    return new Response(null, { status: 101, webSocket: client });
  },

  async handleBidirectional(websocket, reader, writer, key) { // Added websocket parameter
    // Escritura desde WebSocket a destino
    // This event listener should be on the websocket passed from handleWebSocket, not a new one.
    websocket.addEventListener('message', async (event) => {
      try {
        // Ensure event.data is parsed if it's a stringified JSON
        const messageData = typeof event.data === 'string' ? JSON.parse(event.data) : event.data;

        // Check if messageData is for data transmission (not 'init')
        if (messageData.iv && messageData.data) {
            const { iv, data } = messageData;
            const decrypted = await crypto.subtle.decrypt(
              { name: 'AES-GCM', iv: base64ToArrayBuffer(iv) },
              key,
              base64ToArrayBuffer(data)
            );
            await writer.write(decrypted);
        }
      } catch (e) {
        // console.error("WebSocket to destination error:", e); // Optional: log the error
        // Consider how to handle writer errors, e.g., writer.close();
        // If writer.close() can throw, wrap it in try/catch
        try {
            await writer.close();
        } catch (closeError) {
            // console.error("Error closing writer:", closeError);
        }
      }
    });

    // Lectura desde destino a WebSocket
    try {
        while (true) {
          const { value, done } = await reader.read();
          if (done) break;

          const iv = crypto.getRandomValues(new Uint8Array(12));
          const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key,
            value
          );

          websocket.send(JSON.stringify({
            iv: arrayBufferToBase64(iv),
            data: arrayBufferToBase64(encrypted)
          }));
        }
    } catch (e) {
        // console.error("Destination to WebSocket error:", e); // Optional: log the error
    } finally {
        // Ensure websocket is closed if reader is done or errors out
        if (websocket.readyState === WebSocket.OPEN) {
            websocket.close(1000, "Stream finished");
        }
        // Ensure reader is cancelled if not already done
        // await reader.cancel(); // This might be needed depending on the socket implementation
    }
  }
};

// Funciones de utilidad
function base64ToArrayBuffer(base64) {
  return Uint8Array.from(atob(base64), c => c.charCodeAt(0)).buffer;
}

function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

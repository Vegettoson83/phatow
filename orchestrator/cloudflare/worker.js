// phantom_worker.js - Cloudflare Worker Script (Compatible with new Python Client)

// Helper to convert ArrayBuffer to Base64 String
function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

// Helper to convert Base64 String to ArrayBuffer
function base64ToArrayBuffer(base64) {
  const binary_string = atob(base64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
}

// Simple cookie parser
function parseCookies(request) {
  const cookieHeader = request.headers.get('Cookie');
  if (!cookieHeader) return {};
  return Object.fromEntries(
    cookieHeader.split(';').map(c => c.trim().split('=').map(decodeURIComponent))
  );
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    try {
      if (url.pathname === '/phantom-init' && request.method === 'POST') {
        return this.handlePhantomInit(request, env);
      }
      if (url.pathname === '/phantom-handshake' && request.method === 'GET') {
        return this.handlePhantomHandshake(request, env);
      }
      if (url.pathname === '/tunnel') {
        // This requires WebSocket upgrade
        const upgradeHeader = request.headers.get('Upgrade');
        if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
          return new Response('Expected WebSocket upgrade', { status: 426 });
        }
        // Delegate to WebSocket handler (which might be part of this object or a separate one)
        return this.handleTunnelWebSocket(request, env, ctx);
      }
      return new Response('Phantom Worker: Endpoint not found or method not allowed.', { status: 404 });
    } catch (e) {
      console.error(`Worker Error: ${e.stack}`);
      return new Response(`Worker Error: ${e.message}`, { status: 500 });
    }
  },

  async handlePhantomInit(request, env) {
    console.log("Received /phantom-init request");
    try {
      const clientPublicKeyBytes = await request.arrayBuffer();
      if (!clientPublicKeyBytes || clientPublicKeyBytes.byteLength === 0) {
        return new Response('Client public key is missing or empty.', { status: 400 });
      }
      console.log(`Client public key received (${clientPublicKeyBytes.byteLength} bytes)`);

      // Generate server's P-256 key pair for ECDH
      const serverKeyPair = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true, // exportable
        ['deriveKey', 'deriveBits']
      );

      // Export server's public key to send to client
      const serverPublicKeyBytes = await crypto.subtle.exportKey(
        'raw', // Using 'raw' for uncompressed point, client expects X9.62 uncompressed
        serverKeyPair.publicKey
      );

      // The client expects X9.62 uncompressed format. 'raw' gives x and y.
      // For P-256, 'raw' format is usually the concatenation of x and y coordinates.
      // An uncompressed point starts with 0x04.
      // If crypto.subtle.exportKey('raw', key.publicKey) for P-256 returns just x||y,
      // we might need to prepend 0x04 if the client strictly expects it.
      // However, Python's cryptography library's from_encoded_point for SECP256R1
      // can often handle raw x||y if the curve is specified.
      // Let's assume for now client can handle raw x||y. If not, prepend 0x04.
      // Example: const finalServerPubKey = new Uint8Array([0x04, ...new Uint8Array(serverPublicKeyBytes)]);

      // Import client's public key
      const clientPublicKey = await crypto.subtle.importKey(
        'raw', // Client sends X9.62 uncompressed, which is 0x04 followed by x and y.
               // 'raw' here expects just x and y. Python client needs to send raw x||y or worker needs to strip 0x04.
               // Python client: public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
               // This format includes the 0x04 prefix. We need to strip it for 'raw' import.
        clientPublicKeyBytes.slice(1), // Assuming clientPublicKeyBytes[0] is 0x04
        { name: 'ECDH', namedCurve: 'P-256' },
        false, // not extractable
        [] // no usages for imported public key other than derive
      );

      // Derive shared secret
      const sharedSecret = await crypto.subtle.deriveBits(
        { name: 'ECDH', public: clientPublicKey },
        serverKeyPair.privateKey,
        256 // length in bits for the derived secret
      );

      // Derive symmetric key using HKDF (mirroring client's derivation)
      const hkdfKey = await crypto.subtle.importKey(
        'raw',
        sharedSecret,
        { name: 'HKDF' },
        false,
        ['deriveKey']
      );
      const aesKey = await crypto.subtle.deriveKey(
        {
          name: 'HKDF',
          salt: new Uint8Array(), // Empty salt, matching client
          info: new TextEncoder().encode('phantom_proxy_session'), // Matching client
          hash: 'SHA-256',
        },
        hkdfKey,
        { name: 'AES-GCM', length: 256 }, // AES-256-GCM
        false, // not exportable
        ['encrypt', 'decrypt']
      );

      const sessionId = crypto.randomUUID();

      // Store session details: AES key, and potentially other state.
      // KV has a minimum 60s TTL. For very short lived keys, consider other options if available or manage expiry.
      await env.SESSIONS.put(
        `session:${sessionId}`,
        arrayBufferToBase64(await crypto.subtle.exportKey('raw', aesKey)), // Store AES key as base64
        { expirationTtl: 300 } // Session valid for 5 minutes
      );
       await env.SESSIONS.put( // Store private key for WebSocket phase if needed, or re-derive.
         `server_pk:${sessionId}`,
         arrayBufferToBase64(await crypto.subtle.exportKey('pkcs8', serverKeyPair.privateKey)),
         { expirationTtl: 300 }
       );


      console.log(`Session ${sessionId} created. AES key derived and stored.`);

      return new Response(
        JSON.stringify({
          session_id: sessionId,
          server_key: arrayBufferToBase64(serverPublicKeyBytes), // Send raw P-256 public key (x||y)
        }),
        {
          headers: { 'Content-Type': 'application/json' },
          status: 200,
        }
      );
    } catch (e) {
      console.error(`Error in /phantom-init: ${e.stack}`);
      return new Response(`Init Error: ${e.message}`, { status: 500 });
    }
  },

  async handlePhantomHandshake(request, env) {
    console.log("Received /phantom-handshake request");
    const cookies = parseCookies(request);
    const sessionId = cookies['phantom-sid']; // Client uses 'phantom-sid'

    if (!sessionId) {
      return new Response('Session ID cookie missing.', { status: 400 });
    }

    const storedKeyB64 = await env.SESSIONS.get(`session:${sessionId}`);
    if (!storedKeyB64) {
      return new Response('Invalid or expired session ID.', { status: 403 });
    }
    // If key exists, handshake is considered successful by its presence.
    console.log(`Handshake confirmed for session ${sessionId}`);
    return new Response('HANDSHAKE_SUCCESS', { status: 200 });
  },

  async handleTunnelWebSocket(request, env, ctx) {
    console.log("Attempting WebSocket upgrade for /tunnel");
    const cookies = parseCookies(request);
    const sessionId = cookies['phantom-sid'];

    if (!sessionId) {
      return new Response('WebSocket handshake failed: Session ID cookie missing.', { status: 400 });
    }

    const aesKeyB64 = await env.SESSIONS.get(`session:${sessionId}`);
    if (!aesKeyB64) {
      return new Response('WebSocket handshake failed: Invalid or expired session.', { status: 403 });
    }

    const aesKey = await crypto.subtle.importKey(
      'raw',
      base64ToArrayBuffer(aesKeyB64),
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
    console.log(`AES key retrieved for WebSocket session ${sessionId}`);

    const pair = new WebSocketPair();
    const [clientWs, serverWs] = Object.values(pair);

    serverWs.accept();
    console.log("WebSocket connection accepted.");

    // Asynchronously handle the bidirectional pipe
    ctx.waitUntil(this.pipeData(serverWs, aesKey, env, sessionId));

    return new Response(null, { status: 101, webSocket: clientWs });
  },

  async pipeData(websocket, aesKey, env, sessionId) {
    let remoteSocket; // TCP socket to the target destination
    let targetAddress; // To store "host:port"

    // Function to encrypt data for sending to client
    const encryptForClient = async (data) => {
      const iv = crypto.getRandomValues(new Uint8Array(12)); // AES-GCM standard nonce size
      const encryptedData = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        aesKey,
        data
      );
      // Prepend IV to ciphertext
      const payload = new Uint8Array(iv.byteLength + encryptedData.byteLength);
      payload.set(iv, 0);
      payload.set(new Uint8Array(encryptedData), iv.byteLength);
      return payload.buffer;
    };

    // Function to decrypt data received from client
    const decryptFromClient = async (data) => {
      const iv = data.slice(0, 12);
      const ciphertext = data.slice(12);
      return crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: new Uint8Array(iv) }, // Ensure IV is Uint8Array
        aesKey,
        ciphertext
      );
    };

    // Listen for messages from the client (via WebSocket)
    websocket.addEventListener('message', async event => {
      try {
        if (!(event.data instanceof ArrayBuffer)) {
           console.error("Received non-ArrayBuffer WebSocket message. Closing.");
           websocket.close(1003, "Unsupported data type");
           return;
        }

        const decryptedData = await decryptFromClient(event.data);

        if (!remoteSocket) {
          // First message is the target destination "host:port"
          targetAddress = new TextDecoder().decode(decryptedData);
          console.log(`Session ${sessionId}: Decrypted target address: ${targetAddress}`);

          const [host, portStr] = targetAddress.split(':');
          const port = parseInt(portStr, 10);

          if (!host || isNaN(port)) {
            console.error(`Session ${sessionId}: Invalid target address format: ${targetAddress}`);
            websocket.close(1008, "Invalid target address format");
            return;
          }

          try {
            // `connect` is a Cloudflare Workers API for outbound TCP sockets
            remoteSocket = connect({ hostname: host, port: port });
            console.log(`Session ${sessionId}: TCP connection established to ${host}:${port}`);

            // Pipe data from remote TCP socket back to client via WebSocket
            const reader = remoteSocket.readable.getReader();
            (async () => {
              try {
                while (true) {
                  const { done, value } = await reader.read();
                  if (done) {
                    console.log(`Session ${sessionId}: Remote TCP connection closed by target ${targetAddress}.`);
                    websocket.close(1000, "Remote TCP connection closed");
                    break;
                  }
                  const encryptedReply = await encryptForClient(value);
                  websocket.send(encryptedReply);
                }
              } catch (e) {
                console.error(`Session ${sessionId}: Error reading from remote TCP socket ${targetAddress}: ${e.stack}`);
                if (websocket.readyState === WebSocket.OPEN) {
                   websocket.close(1011, "TCP read error");
                }
              } finally {
                reader.releaseLock(); // Release reader lock
                if (remoteSocket && remoteSocket.writable && !remoteSocket.writable.locked) {
                    try { await remoteSocket.close(); } catch(e) {/*ignore*/}
                }
              }
            })();
          } catch (e) {
            console.error(`Session ${sessionId}: Failed to connect to target ${targetAddress}: ${e.stack}`);
            websocket.close(1011, `Failed to connect to target: ${e.message}`);
            return;
          }
        } else {
          // Subsequent messages are data to forward to the remote TCP socket
          if (remoteSocket && remoteSocket.writable) {
            const writer = remoteSocket.writable.getWriter();
            try {
                await writer.write(decryptedData);
            } finally {
                writer.releaseLock(); // Release writer lock
            }
          } else {
            console.error(`Session ${sessionId}: remoteSocket not writable or not available for data forwarding.`);
            // Consider closing if this state is unexpected
          }
        }
      } catch (e) {
        console.error(`Session ${sessionId}: Error processing client message: ${e.stack}`);
        if (e instanceof DOMException && e.name === 'OperationError' && e.message.includes('ciphertext integrity')) {
            websocket.close(1008, "Decryption failed - integrity check");
        } else if (websocket.readyState === WebSocket.OPEN) {
            websocket.close(1011, "Internal processing error");
        }
      }
    });

    websocket.addEventListener('close', event => {
      console.log(`Session ${sessionId}: WebSocket closed by client or network. Code: ${event.code}, Reason: ${event.reason}`);
      if (remoteSocket) {
        // Ensure remote TCP socket is closed if WebSocket closes
        try {
          remoteSocket.close();
        } catch (e) {
          // console.error(`Session ${sessionId}: Error closing remote TCP socket on WebSocket close: ${e.stack}`);
        }
      }
      // Clean up session data from KV if necessary, though TTL will handle it eventually.
      // env.SESSIONS.delete(`session:${sessionId}`);
      // env.SESSIONS.delete(`server_pk:${sessionId}`);
    });

    websocket.addEventListener('error', event => {
      // Event might be a simple ErrorEvent, not much detail.
      console.error(`Session ${sessionId}: WebSocket error occurred. ${event.message || ''}`);
      if (remoteSocket) {
        try {
          remoteSocket.close();
        } catch (e) {
          // console.error(`Session ${sessionId}: Error closing remote TCP socket on WebSocket error: ${e.stack}`);
        }
      }
    });
  },
};

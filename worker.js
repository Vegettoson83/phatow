addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

const sessions = new Map()

// Cleanup old sessions every 5 minutes
setInterval(() => {
  const now = Date.now()
  for (const [sessionId, session] of sessions.entries()) {
    if (now - session.createdAt > 3600000) { // 1 hour
      sessions.delete(sessionId)
      console.log(`Cleaned up expired session: ${sessionId}`)
    }
  }
}, 300000)

async function handleRequest(request) {
  const url = new URL(request.url)

  // Add CORS headers for all responses
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Cookie',
  }

  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders })
  }

  if (url.pathname === '/') {
    return new Response('Phantom Proxy Worker v1.0 - Active', {
      headers: { ...corsHeaders, 'Content-Type': 'text/plain' }
    })
  }

  if (url.pathname === '/status') {
    return new Response(JSON.stringify({
      status: 'active',
      sessions: sessions.size,
      timestamp: new Date().toISOString()
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    })
  }

  if (url.pathname === '/phantom-init') {
    return handleKeyExchange(request, corsHeaders)
  }

  if (url.pathname === '/phantom-handshake') {
    return handleHandshakeConfirmation(request, corsHeaders)
  }

  if (url.pathname === '/tunnel') {
    return handleTunnel(request)
  }

  return new Response('Not found', {
    status: 404,
    headers: corsHeaders
  })
}

async function handleKeyExchange(request, corsHeaders) {
  try {
    if (request.method !== 'POST') {
      return new Response('Method not allowed', {
        status: 405,
        headers: corsHeaders
      })
    }

    const clientKey = new Uint8Array(await request.arrayBuffer())

    if (clientKey.length !== 65) { // Uncompressed P-256 key
      return new Response('Invalid key format', {
        status: 400,
        headers: corsHeaders
      })
    }

    // Generate server key pair using P-256 (same as client)
    const serverKeyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-256'
      },
      true,
      ['deriveKey']
    )

    const serverPublicKey = await crypto.subtle.exportKey(
      'raw',
      serverKeyPair.publicKey
    )

    const sessionId = crypto.randomUUID()

    sessions.set(sessionId, {
      clientKey,
      serverKeyPair,
      createdAt: Date.now()
    })

    console.log(`New session created: ${sessionId}`)

    return new Response(JSON.stringify({
      session_id: sessionId,
      server_key: arrayBufferToBase64(serverPublicKey)
    }), {
      headers: {
        ...corsHeaders,
        'Content-Type': 'application/json',
        'Set-Cookie': `phantom-sid=${sessionId}; HttpOnly; Secure; Max-Age=3600; SameSite=None`
      }
    })
  } catch (e) {
    console.error('Key exchange error:', e)
    return new Response('Key exchange failed', {
      status: 400,
      headers: corsHeaders
    })
  }
}

async function handleHandshakeConfirmation(request, corsHeaders) {
  try {
    const sessionId = getSessionId(request)
    if (!sessionId || !sessions.has(sessionId)) {
      return new Response('Invalid session', {
        status: 400,
        headers: corsHeaders
      })
    }

    const session = sessions.get(sessionId)

    // Import client public key using P-256
    const clientPublicKey = await crypto.subtle.importKey(
      'raw',
      session.clientKey,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    )

    // Derive shared key
    const derivedKey = await crypto.subtle.deriveKey(
      {
        name: 'ECDH',
        public: clientPublicKey
      },
      session.serverKeyPair.privateKey,
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(),
        info: new TextEncoder().encode('phantom_proxy_session')
      },
      false,
      ['encrypt', 'decrypt']
    )

    // Convert HKDF result to AES-GCM key
    const keyMaterial = await crypto.subtle.exportKey('raw', derivedKey)
    const aesKey = await crypto.subtle.importKey(
      'raw',
      keyMaterial.slice(0, 32), // Take first 32 bytes for AES-256
      { name: 'AES-GCM' },
      false,
      ['encrypt', 'decrypt']
    )

    session.derivedKey = aesKey

    console.log(`Handshake completed for session: ${sessionId}`)

    return new Response('HANDSHAKE_SUCCESS', {
      headers: {
        ...corsHeaders,
        'Content-Type': 'text/plain'
      }
    })
  } catch (e) {
    console.error('Handshake confirmation error:', e)
    return new Response('Handshake failed', {
      status: 400,
      headers: corsHeaders
    })
  }
}

async function handleTunnel(request) {
  const sessionId = getSessionId(request)
  if (!sessionId || !sessions.has(sessionId)) {
    return new Response('Session required', { status: 403 })
  }

  const session = sessions.get(sessionId)
  if (!session.derivedKey) {
    return new Response('Handshake not completed', { status: 403 })
  }

  const upgradeHeader = request.headers.get('Upgrade')
  if (upgradeHeader !== 'websocket') {
    return new Response('Expected websocket', { status: 426 })
  }

  const [client, server] = Object.values(new WebSocketPair())
  server.accept()

  console.log(`WebSocket tunnel opened for session: ${sessionId}`)

  let targetSocket = null

  server.addEventListener('message', async event => {
    try {
      if (event.data instanceof ArrayBuffer) {
        const data = new Uint8Array(event.data)

        if (data.length < 28) { // IV (12) + tag (16) minimum
          server.close(1003, 'Invalid data format')
          return
        }

        const iv = data.slice(0, 12)
        const tag = data.slice(data.length - 16)
        const ciphertext = data.slice(12, data.length - 16)

        const combined = new Uint8Array(ciphertext.length + tag.length)
        combined.set(ciphertext)
        combined.set(tag, ciphertext.length)

        const decrypted = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv },
          session.derivedKey,
          combined
        )

        if (!session.target) {
          // First message contains target host:port
          const target = new TextDecoder().decode(decrypted)
          session.target = target
          console.log(`Target set for ${sessionId}: ${target}`)

          // Connect to target
          const [host, port] = target.split(':')
          try {
            targetSocket = connect({
              hostname: host,
              port: parseInt(port)
            })

            targetSocket.addEventListener('message', async event => {
              try {
                const responseData = new Uint8Array(event.data)
                const responseIV = crypto.getRandomValues(new Uint8Array(12))

                const encrypted = await crypto.subtle.encrypt(
                  { name: 'AES-GCM', iv: responseIV },
                  session.derivedKey,
                  responseData
                )

                const encryptedArray = new Uint8Array(encrypted)
                const responseTag = encryptedArray.slice(encryptedArray.length - 16)
                const responseCiphertext = encryptedArray.slice(0, encryptedArray.length - 16)

                const payload = new Uint8Array(12 + responseCiphertext.length + 16)
                payload.set(responseIV)
                payload.set(responseCiphertext, 12)
                payload.set(responseTag, 12 + responseCiphertext.length)

                if (server.readyState === WebSocket.READY_STATE_OPEN) {
                  server.send(payload)
                }
              } catch (e) {
                console.error('Error processing target response:', e)
                server.close(1011, 'Processing error')
              }
            })

            targetSocket.addEventListener('close', () => {
              server.close()
            })

            targetSocket.addEventListener('error', () => {
              server.close(1011, 'Target connection failed')
            })

          } catch (e) {
            console.error(`Failed to connect to ${target}:`, e)
            server.close(1011, 'Target unreachable')
          }
          return
        }

        // Forward data to target
        if (targetSocket && targetSocket.readyState === WebSocket.READY_STATE_OPEN) {
          targetSocket.send(decrypted)
        }

      }
    } catch (e) {
      console.error('Tunnel message error:', e)
      server.close(1011, 'Failed to decrypt')
    }
  })

  server.addEventListener('close', (event) => {
    console.log(`WebSocket tunnel closed for session: ${sessionId}`)
    if (targetSocket) {
      targetSocket.close()
    }
    sessions.delete(sessionId)
  })

  server.addEventListener('error', (event) => {
    console.error(`WebSocket error for session ${sessionId}:`, event)
  })

  return new Response(null, {
    status: 101,
    webSocket: client
  })
}

function getSessionId(request) {
  const cookie = request.headers.get('Cookie')
  if (!cookie) return null
  const match = cookie.match(/phantom-sid=([^;]+)/)
  return match ? match[1] : null
}

function arrayBufferToBase64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
}

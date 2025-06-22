addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

const sessions = new Map()

async function handleRequest(request) {
  const url = new URL(request.url)

  if (url.pathname === '/phantom-init') {
    return handleKeyExchange(request)
  }

  if (url.pathname === '/phantom-handshake') {
    return handleHandshakeConfirmation(request)
  }

  if (url.pathname === '/tunnel') {
    return handleTunnel(request)
  }

  return camouflageResponse(request)
}

async function handleKeyExchange(request) {
  try {
    const clientKey = new Uint8Array(await request.arrayBuffer())

    // Generar par de claves P-256
    const serverKeyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-256'
      },
      true,
      ['deriveKey']
    )

    const serverPublicKey = await crypto.subtle.exportKey(
      'raw', // para obtener formato X9.62 sin compresión
      serverKeyPair.publicKey
    )

    const sessionId = crypto.randomUUID()

    sessions.set(sessionId, {
      clientKey,
      serverKeyPair,
      createdAt: Date.now()
    })

    return new Response(JSON.stringify({
      session_id: sessionId,
      server_key: arrayBufferToBase64(serverPublicKey)
    }), {
      headers: {
        'Content-Type': 'application/json',
        'Set-Cookie': `phantom-sid=${sessionId}; HttpOnly; Secure; Max-Age=3600`
      }
    })
  } catch (e) {
    return new Response('Key exchange failed', { status: 400 })
  }
}

async function handleHandshakeConfirmation(request) {
  const sessionId = getSessionId(request)
  if (!sessionId || !sessions.has(sessionId)) {
    return new Response('Invalid session', { status: 400 })
  }

  const session = sessions.get(sessionId)

  // Importar clave pública cliente
  const clientPublicKey = await crypto.subtle.importKey(
    'raw',
    session.clientKey,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  )

  // Derivar clave compartida
  const derivedKey = await crypto.subtle.deriveKey(
    {
      name: 'ECDH',
      public: clientPublicKey
    },
    session.serverKeyPair.privateKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  )

  session.derivedKey = derivedKey

  return new Response('HANDSHAKE_SUCCESS', {
    headers: { 'Content-Type': 'text/plain' }
  })
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

  const [client, server] = Object.values(new WebSocketPair())
  server.accept()

  // Variables para TCP (simulado con sockets TCP en entorno Cloudflare no disponible)
  let targetSocket = null

  server.addEventListener('message', async event => {
    if (event.data instanceof ArrayBuffer) {
      try {
        const data = new Uint8Array(event.data)

        // Descifrar mensaje
        const iv = data.slice(0, 12)
        const encrypted = data.slice(12)
        const decrypted = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv },
          session.derivedKey,
          encrypted
        )

        // El primer mensaje es el destino "host:port"
        if (!session.target) {
          const targetStr = new TextDecoder().decode(decrypted)
          const [host, portStr] = targetStr.split(':')
          session.target = { host, port: parseInt(portStr, 10) }

          // Aquí se debería conectar al host:port pero Workers no permite TCP real
          // En entorno real habría que crear socket TCP y vincular eventos
          // Por ahora solo confirmamos que está listo
          server.send(new TextEncoder().encode('CONNECTED'))

          return
        }

        // Aquí reenviarías datos al socket TCP destino si estuviera disponible
        // Como ejemplo, simplemente echo de vuelta cifrado
        const nonce = crypto.getRandomValues(new Uint8Array(12))
        const encryptedReply = await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv: nonce },
          session.derivedKey,
          decrypted // echo de vuelta
        )
        const payload = new Uint8Array(nonce.length + encryptedReply.byteLength)
        payload.set(nonce)
        payload.set(new Uint8Array(encryptedReply), nonce.length)

        server.send(payload)
      } catch (err) {
        server.close(1011, 'Decryption failed')
      }
    }
  })

  server.addEventListener('close', () => {
    sessions.delete(sessionId)
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
  let binary = ''
  const bytes = new Uint8Array(buffer)
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary)
}

function camouflageResponse(request) {
  const url = new URL(request.url)
  if (url.pathname.includes('/recaptcha')) {
    return new Response(JSON.stringify({ success: true }), {
      headers: { 'Content-Type': 'application/json' }
    })
  }
  return new Response('Not found', { status: 404 })
}

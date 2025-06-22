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

  return new Response('Not found', { status: 404 })
}

async function handleKeyExchange(request) {
  try {
    const clientKey = new Uint8Array(await request.arrayBuffer())

    const serverKeyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'X25519'
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

  const clientPublicKey = await crypto.subtle.importKey(
    'raw',
    session.clientKey,
    { name: 'ECDH', namedCurve: 'X25519' },
    false,
    []
  )

  const derivedKey = await crypto.subtle.deriveKey(
    {
      name: 'ECDH',
      public: clientPublicKey
    },
    session.serverKeyPair.privateKey,
    {
      name: 'AES-GCM',
      length: 256
    },
    false,
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

  server.addEventListener('message', async event => {
    if (event.data instanceof ArrayBuffer) {
      try {
        const data = new Uint8Array(event.data)
        const iv = data.slice(0, 12)
        const ciphertext = data.slice(12)
        const decrypted = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv },
          session.derivedKey,
          ciphertext
        )

        if (!session.target) {
          const target = new TextDecoder().decode(decrypted)
          session.target = target
          server.send(new TextEncoder().encode('READY'))
          return
        }

        const responseIV = crypto.getRandomValues(new Uint8Array(12))
        const encryptedReply = await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv: responseIV },
          session.derivedKey,
          decrypted
        )
        const payload = new Uint8Array(responseIV.length + encryptedReply.byteLength)
        payload.set(responseIV)
        payload.set(new Uint8Array(encryptedReply), responseIV.length)

        server.send(payload)
      } catch (_) {
        server.close(1011, 'Failed to decrypt')
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
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
}

}

// phantom-worker.js
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

// Almacén de sesiones
const sessions = new Map()

async function handleRequest(request) {
  const url = new URL(request.url)
  
  // 1. Intercambio de claves
  if (url.pathname === '/phantom-init') {
    return handleKeyExchange(request)
  }
  
  // 2. Confirmación handshake
  if (url.pathname === '/phantom-handshake') {
    return handleHandshakeConfirmation(request)
  }
  
  // 3. Túnel WebSocket
  if (url.pathname === '/tunnel') {
    return handleTunnel(request)
  }
  
  // 4. Respuestas de camuflaje
  return camouflageResponse(request)
}

async function handleKeyExchange(request) {
  try {
    const clientKey = await request.arrayBuffer()
    const sessionId = crypto.randomUUID()
    
    // Generar par de claves
    const serverKeyPair = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "X25519" },
      true,
      ["deriveKey"]
    )
    
    const serverPublicKey = await crypto.subtle.exportKey(
      "raw",
      serverKeyPair.publicKey
    )
    
    // Almacenar sesión
    sessions.set(sessionId, {
      clientKey: new Uint8Array(clientKey),
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
  } catch (err) {
    return new Response('Key exchange failed', { status: 400 })
  }
}

async function handleHandshakeConfirmation(request) {
  const sessionId = getSessionId(request)
  if (!sessionId || !sessions.has(sessionId)) {
    return new Response('Invalid session', { status: 400 })
  }
  
  const session = sessions.get(sessionId)
  
  // Derivar clave compartida
  const derivedKey = await deriveSharedKey(session)
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
  
  // Crear WebSocket
  const [client, server] = Object.values(new WebSocketPair())
  server.accept()
  
  server.addEventListener('message', event => {
    handleWebSocketMessage(event, server, session)
  })
  
  return new Response(null, {
    status: 101,
    webSocket: client
  })
}

async function handleWebSocketMessage(event, server, session) {
  if (event.data instanceof ArrayBuffer) {
    const data = new Uint8Array(event.data)
    
    try {
      // Descifrar datos
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: data.slice(0, 12) },
        session.derivedKey,
        data.slice(12)
      )
      
      // Primer mensaje contiene el destino
      if (!session.target) {
        const target = new TextDecoder().decode(decrypted)
        const [host, port] = target.split(':')
        session.target = { host, port: parseInt(port) }
        connectToTarget(server, session)
        return
      }
      
      // Reenviar datos al socket TCP
      if (session.tcpSocket) {
        session.tcpSocket.write(new Uint8Array(decrypted))
      }
    } catch (e) {
      console.error('Decryption error:', e)
      server.close(1011, 'Decryption failed')
    }
  }
}

async function connectToTarget(server, session) {
  try {
    // Conectar al destino real
    const tcpSocket = connect({
      hostname: session.target.host,
      port: session.target.port
    })
    
    session.tcpSocket = tcpSocket
    
    // Manejar datos del destino
    tcpSocket.addEventListener('data', async (data) => {
      try {
        // Cifrar datos
        const iv = crypto.getRandomValues(new Uint8Array(12))
        const encrypted = await crypto.subtle.encrypt(
          { name: "AES-GCM", iv },
          session.derivedKey,
          data
        )
        
        // Combinar IV + datos cifrados
        const payload = new Uint8Array(iv.length + encrypted.byteLength)
        payload.set(iv)
        payload.set(new Uint8Array(encrypted), iv.length)
        
        server.send(payload)
      } catch (e) {
        console.error('Encryption error:', e)
      }
    })
    
    tcpSocket.addEventListener('close', () => {
      server.close(1000, 'Target closed')
    })
    
    tcpSocket.addEventListener('error', (err) => {
      console.error('TCP error:', err)
      server.close(1011, 'Target error')
    })
    
  } catch (err) {
    console.error('TCP connection failed:', err)
    server.close(1011, 'Connection failed')
  }
}

// Helper: Derivar clave compartida
async function deriveSharedKey(session) {
  const clientPublicKey = await crypto.subtle.importKey(
    "raw",
    session.clientKey,
    { name: "ECDH", namedCurve: "X25519" },
    false,
    []
  )
  
  return crypto.subtle.deriveKey(
    { name: "ECDH", public: clientPublicKey },
    session.serverKeyPair.privateKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  )
}

// Helper: Obtener ID de sesión de las cookies
function getSessionId(request) {
  const cookieHeader = request.headers.get('Cookie')
  if (!cookieHeader) return null
  const cookies = cookieHeader.split(';')
  for (const cookie of cookies) {
    const [name, value] = cookie.trim().split('=')
    if (name === 'phantom-sid') return value
  }
  return null
}

// Helper: ArrayBuffer a Base64
function arrayBufferToBase64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
}

// Simular respuestas de camuflaje
function camouflageResponse(request) {
  const url = new URL(request.url)
  if (url.pathname.includes('/recaptcha')) {
    return new Response(JSON.stringify({ success: true }), {
      headers: { 'Content-Type': 'application/json' }
    })
  }
  return new Response('Not found', { status: 404 })
}

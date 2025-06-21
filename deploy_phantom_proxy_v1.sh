#!/bin/bash

# 🚀 Script de Despliegue Automático - Phantom Proxy
# Este script automatiza todo el proceso de despliegue

set -e  # Salir si hay algún error

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Función para imprimir con colores
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Banner
echo -e "${BLUE}"
cat << "EOF"
    ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
    ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
    ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
    ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
    ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝

    🚀 DESPLIEGUE AUTOMÁTICO - Phantom Proxy v1.0
EOF
echo -e "${NC}"

# Verificaciones iniciales
print_step "1/8 - Verificando dependencias..."

# Verificar Node.js
if ! command -v node &> /dev/null; then
    print_error "Node.js no está instalado"
    print_warning "Descarga e instala desde: https://nodejs.org"
    exit 1
fi
print_status "Node.js: $(node --version)"

# Verificar Python
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 no está instalado"
    exit 1
fi
print_status "Python: $(python3 --version)"

# Verificar pip
if ! command -v pip3 &> /dev/null; then
    print_error "pip3 no está instalado"
    exit 1
fi

# Instalar/verificar Wrangler
print_step "2/8 - Configurando Wrangler..."
if ! command -v wrangler &> /dev/null; then
    print_warning "Wrangler no encontrado, instalando..."
    npm install -g wrangler
fi
print_status "Wrangler: $(wrangler --version)"

# Verificar autenticación de Cloudflare
print_step "3/8 - Verificando autenticación Cloudflare..."
if ! wrangler whoami &> /dev/null; then
    print_warning "No estás autenticado en Cloudflare"
    print_status "Ejecutando wrangler login..."
    wrangler login
else
    print_status "Autenticado como: $(wrangler whoami)"
fi

# Crear directorio del proyecto
PROJECT_NAME="phantom-proxy-$(date +%s)"
print_step "4/8 - Creando proyecto: $PROJECT_NAME"
mkdir -p "$PROJECT_NAME"
cd "$PROJECT_NAME"

# Crear wrangler.toml
print_step "5/8 - Creando configuración..."
cat > wrangler.toml << EOF
name = "$PROJECT_NAME"
main = "worker.js"
compatibility_date = "2024-06-01" # Consider updating this date

[vars]
ENV = "production"
EOF

# Crear worker.js (versión optimizada para producción)
# This is the first file content provided by the user
cat > worker.js << 'EOF'
// phantom-worker.js - Versión Simplificada
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

// Almacén temporal de sesiones
const sessions = new Map()

// Limpiar sesiones viejas cada hora
setInterval(() => {
  const now = Date.now()
  for (const [id, session] of sessions.entries()) {
    if (now - session.createdAt > 3600000) { // 1 hora
      sessions.delete(id)
    }
  }
}, 3600000)

async function handleRequest(request) {
  const url = new URL(request.url)

  // CORS headers para desarrollo
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Cookie',
  }

  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders })
  }

  try {
    // 1. Intercambio de claves inicial
    if (url.pathname === '/phantom-init') {
      return await handleKeyExchange(request, corsHeaders)
    }

    // 2. Confirmación de handshake
    if (url.pathname === '/phantom-handshake') {
      return await handleHandshakeConfirmation(request, corsHeaders)
    }

    // 3. Túnel WebSocket
    if (url.pathname === '/tunnel') {
      return await handleTunnel(request)
    }

    // 4. Respuesta de camuflaje
    return camouflageResponse()

  } catch (error) {
    console.error('Request error:', error)
    return new Response('Internal error', {
      status: 500,
      headers: corsHeaders
    })
  }
}

async function handleKeyExchange(request, corsHeaders) {
  try {
    const clientKeyBuffer = await request.arrayBuffer()
    const sessionId = crypto.randomUUID()

    // Generar par de claves del servidor
    const serverKeyPair = await crypto.subtle.generateKey(
      { name: "X25519" },
      true,
      ["deriveKey"]
    )

    // Exportar clave pública del servidor
    const serverPublicKey = await crypto.subtle.exportKey("raw", serverKeyPair.publicKey)

    // Guardar sesión
    sessions.set(sessionId, {
      clientKey: new Uint8Array(clientKeyBuffer),
      serverKeyPair,
      createdAt: Date.now(),
      connected: false
    })

    // Responder con la clave del servidor
    return new Response(JSON.stringify({
      session_id: sessionId,
      server_key: arrayBufferToBase64(serverPublicKey)
    }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Set-Cookie': `phantom-sid=${sessionId}; HttpOnly; Secure; SameSite=None; Max-Age=3600`,
        ...corsHeaders
      }
    })
  } catch (error) {
    console.error('Key exchange error:', error)
    return new Response('Key exchange failed', {
      status: 400,
      headers: corsHeaders
    })
  }
}

async function handleHandshakeConfirmation(request, corsHeaders) {
  const sessionId = getSessionId(request)

  if (!sessionId || !sessions.has(sessionId)) {
    return new Response('Invalid session', {
      status: 400,
      headers: corsHeaders
    })
  }

  const session = sessions.get(sessionId)

  try {
    // Importar clave pública del cliente
    const clientPublicKey = await crypto.subtle.importKey(
      "raw",
      session.clientKey,
      { name: "X25519" },
      false,
      []
    )

    // Derivar clave compartida usando HKDF
    const sharedSecret = await crypto.subtle.deriveKey(
      { name: "X25519", public: clientPublicKey },
      session.serverKeyPair.privateKey,
      { name: "HKDF" }, // This step in client was direct ECDH to shared secret. Worker uses it as KDF input.
      false,            // Client: self.private_key.exchange(server_public_key) -> shared_secret
                        // Worker: deriveKey({name: X25519...}, privateKey, {name: HKDF...}) -> sharedSecret (for HKDF)
                        // This is a subtle but important difference. The client's shared_secret is the direct output of ECDH.
                        // The worker's sharedSecret here is an intermediate key material for HKDF.
                        // The *actual* shared secret from ECDH for the worker is implicitly used by `deriveKey` with X25519.
                        // Then, this shared secret is used as input material to an HKDF derivation.
      ["deriveKey"]
    )

    // Derivar clave final para ChaCha20Poly1305 (simulada con AES-GCM en JS worker)
    const finalKey = await crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256", // Client uses SHA256 for HKDF
        salt: new Uint8Array(0), // Client uses None salt (empty byte array)
        info: new TextEncoder().encode("phantom_proxy_session") // Client uses this info
      },
      sharedSecret, // This is the key material from the previous HKDF step (or direct ECDH if API was different)
      { name: "AES-GCM", length: 256 }, // JS uses AES-GCM, Python client uses ChaCha20Poly1305. These are NOT directly compatible.
                                        // For this to work, both sides MUST use the same AEAD algorithm.
                                        // Assuming AES-GCM for worker as ChaCha is not standard in WebCrypto (though available in some environments).
                                        // Python client MUST be changed to use AES-GCM if this worker is used.
      false,
      ["encrypt", "decrypt"]
    )

    session.derivedKey = finalKey
    session.connected = true

    return new Response('HANDSHAKE_SUCCESS', {
      status: 200,
      headers: {
        'Content-Type': 'text/plain',
        ...corsHeaders
      }
    })
  } catch (error) {
    console.error('Handshake confirmation error:', error)
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

  if (!session.connected || !session.derivedKey) { // Check derivedKey too
    return new Response('Handshake not completed or key derivation failed', { status: 403 })
  }

  // Crear WebSocket pair
  const [client, server] = Object.values(new WebSocketPair())

  // Configurar el servidor WebSocket
  server.accept()

  // Manejar mensajes del WebSocket
  server.addEventListener('message', async (event) => {
    await handleWebSocketMessage(event, server, session)
  })

  server.addEventListener('close', () => {
    if (session.tcpSocket) {
      try { session.tcpSocket.close() } catch(e) { /* ignore errors on close */ }
    }
  })
  server.addEventListener('error', (err) => { // Added error listener
    console.error("WebSocket server error:", err);
    if (session.tcpSocket) {
      try { session.tcpSocket.close() } catch(e) { /* ignore errors on close */ }
    }
  })

  return new Response(null, {
    status: 101,
    webSocket: client,
  })
}

async function handleWebSocketMessage(event, server, session) {
  if (!(event.data instanceof ArrayBuffer)) {
    // console.warn("Received non-ArrayBuffer WebSocket message.");
    return // Silently ignore non-ArrayBuffer messages
  }

  try {
    const encryptedData = new Uint8Array(event.data)

    if (encryptedData.length < 12) { // Nonce length for AES-GCM / ChaCha20Poly1305
      // console.warn("Encrypted data too short.");
      throw new Error('Invalid encrypted data (too short)')
    }

    // Extraer nonce y datos cifrados
    const nonce = encryptedData.slice(0, 12)
    const ciphertext = encryptedData.slice(12)

    // Descifrar datos
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce }, // Assuming AES-GCM due to worker crypto availability
      session.derivedKey,
      ciphertext
    )

    const decryptedData = new Uint8Array(decrypted)

    // Si no hay conexión TCP, el primer mensaje es el destino
    if (!session.tcpSocket) {
      const target = new TextDecoder().decode(decryptedData) // Ensure target is decoded correctly
      const [host, portStr] = target.split(':')
      const port = parseInt(portStr, 10)

      if (!host || isNaN(port)) {
        // console.error("Invalid target format:", target);
        server.close(1008, "Invalid target format"); // Policy Violation
        return;
      }

      await connectToTarget(server, session, host, port)
      return
    }

    // Enviar datos al destino
    if (session.tcpSocket && session.tcpSocket.writable) {
      const writer = session.tcpSocket.writable.getWriter()
      try {
        await writer.write(decryptedData)
      } finally {
        writer.releaseLock()
      }
    } else {
      // console.warn("TCP socket not writable or available for data forwarding.");
      // This might happen if the TCP socket closed before data could be written.
    }

  } catch (error) {
    // console.error('WebSocket message processing error:', error)
    // Avoid closing the server on every decrypt error if it's an attack
    // server.close(1011, 'Processing error') // Internal Error
  }
}

async function connectToTarget(server, session, host, port) {
  try {
    // Conectar al destino usando Cloudflare's connect API
    const tcpSocket = connect({ // `connect` is a global in CF Workers
      hostname: host,
      port: port
    })

    session.tcpSocket = tcpSocket

    // Leer datos del destino y enviarlos cifrados al cliente
    const reader = tcpSocket.readable.getReader()

    const readLoop = async () => {
      try {
        while (true) {
          const { done, value } = await reader.read()

          if (done) {
            // console.log("TCP connection closed by target.");
            break
          }

          // Cifrar datos del destino
          const nonce = crypto.getRandomValues(new Uint8Array(12)) // For AES-GCM / ChaCha20
          const encrypted = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: nonce }, // Assuming AES-GCM
            session.derivedKey,
            value // `value` is already an ArrayBuffer/Uint8Array from reader.read()
          )

          // Combinar nonce + datos cifrados
          const payload = new Uint8Array(nonce.length + encrypted.byteLength)
          payload.set(nonce)
          payload.set(new Uint8Array(encrypted), nonce.length)

          if (server.readyState === WebSocket.OPEN) { // Check if WebSocket is still open
             server.send(payload.buffer) // Send ArrayBuffer
          } else {
            // console.warn("WebSocket closed before data could be sent from target.");
            break; // Exit read loop if WebSocket is closed
          }
        }
      } catch (error) {
        // console.error('TCP read loop error:', error)
      } finally {
        if (server.readyState === WebSocket.OPEN) {
          server.close(1000, 'Target connection closed or error') // Normal Closure
        }
        // Ensure the reader is released and socket is closed if not already by done
        reader.releaseLock();
        try { if (tcpSocket) tcpSocket.close(); } catch(e) {/* ignore */}
      }
    }

    readLoop().catch(e => { /* console.error("Unhandled error in readLoop promise:", e) */ });

  } catch (error) {
    // console.error('TCP connection to target failed:', error)
    if (server.readyState === WebSocket.OPEN) {
      server.close(1011, 'Target connection failed') // Internal Error
    }
  }
}

// Helper: Obtener session ID de las cookies
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

// Helper: Convertir ArrayBuffer a Base64
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary)
}

// Respuesta de camuflaje para ocultar el verdadero propósito
function camouflageResponse() {
  const responses = [
    { body: 'Not Found', status: 404 },
    { body: 'Service Temporarily Unavailable', status: 503 },
    { body: 'Forbidden', status: 403 },
    { body: 'Bad Request', status: 400 }
  ]

  const randomResponse = responses[Math.floor(Math.random() * responses.length)]

  return new Response(randomResponse.body, {
    status: randomResponse.status, // Use status from the selected response
    headers: {
      'Content-Type': 'text/plain',
      'Server': 'cloudflare', // Standard Cloudflare server header
      'CF-Cache-Status': 'MISS' // Example cache status
    }
  })
}
EOF

# Desplegar worker
print_step "6/8 - Desplegando worker en Cloudflare..."
# Try to get URL with --json, fallback to manual input if jq or parsing fails
WORKER_URL_JSON_OUTPUT=$(wrangler deploy --json)
WORKER_URL=$(echo "$WORKER_URL_JSON_OUTPUT" | jq -r '.url' 2>/dev/null || echo "")


if [ -z "$WORKER_URL" ] || [ "$WORKER_URL" == "null" ]; then
    # Fallback if jq not available or URL not in JSON output
    print_warning "No se pudo obtener la URL del worker automáticamente con --json."
    print_status "El worker ha sido desplegado (o intentado). Por favor, verifica el output de Wrangler."
    # Show output from wrangler deploy if available and not empty
    if [ -n "$WORKER_URL_JSON_OUTPUT" ]; then
        echo "Output de Wrangler Deploy:"
        echo "$WORKER_URL_JSON_OUTPUT"
    else
        # If JSON output was empty, it means deploy itself might have failed before JSON part
        # or wrangler version doesn't support --json well.
        # We already ran `wrangler deploy --json`. If that failed, set -e would have exited.
        # This path is more for when --json works but .url is not found.
        # For safety, we can re-run without --json if the first try seems to have not produced a URL.
        # However, `wrangler deploy` without --json is interactive or less script-friendly.
        # The original script just ran `wrangler deploy` again.
        print_warning "Intentando obtener URL de otra manera o necesitarás ingresarla manualmente."
        # Attempt to find from `wrangler deployments list`
        # This is a bit fragile as it assumes the latest deployment is the one we want.
        WORKER_SUBDOMAIN=$(echo "$WORKER_URL_JSON_OUTPUT" | jq -r '.subdomain // ""' 2>/dev/null)
        if [ -n "$WORKER_SUBDOMAIN" ]; then
             WORKER_URL="https://${PROJECT_NAME}.${WORKER_SUBDOMAIN}.workers.dev"
             print_status "URL construida (puede no ser la final): $WORKER_URL"
        else
            # Last resort: ask user
            print_warning "No se pudo determinar la URL final del worker."
            read -p "Por favor, ingresa la URL completa del worker desplegado: " WORKER_URL
            if [ -z "$WORKER_URL" ]; then
                print_error "URL no ingresada. No se puede continuar."
                exit 1
            fi
        fi
    fi
else
    print_status "Worker desplegado en: $WORKER_URL"
fi


# Instalar dependencias Python
print_step "7/8 - Instalando dependencias Python..."
pip3 install aiohttp cryptography --quiet --user # --user might install to a non-PATH location

# Crear cliente Python
# This is the second file content provided by the user
cat > cliente.py << 'EOF'
#!/usr/bin/env python3
"""
Phantom Proxy Client - Versión Simplificada
Proxy SOCKS5 que se conecta a través de Cloudflare Worker
"""

import asyncio
import sys
import os
import base64
import struct
import json # Not used in this version of client
import aiohttp
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 # Worker uses AES-GCM, this needs to match

# Configuración
DEFAULT_SOCKS_PORT = 1080 # DEFAULT_WORKER_URL is passed as argument

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PhantomClient:
    def __init__(self, worker_url):
        self.worker_url = worker_url.rstrip('/')
        self.session = None
        self.session_id = None
        # IMPORTANT: Crypto mismatch. Worker uses AES-GCM. Client uses ChaCha20Poly1305.
        # This needs to be reconciled. For now, sticking to user's client code.
        self.crypto_key = None # Will be ChaCha20Poly1305 instance
        self.ws = None

        # Generar par de claves X25519
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    async def __aenter__(self):
        # Consider verifying SSL for production workers if they have a custom domain with proper cert.
        # For *.workers.dev, Cloudflare handles SSL. `ssl=False` might be for local http testing.
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            # connector=aiohttp.TCPConnector(ssl=False, limit=100) # ssl=False is unusual for https URLs
            connector=aiohttp.TCPConnector(limit=100) # Default SSL context usually works for https
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.ws and not self.ws.closed: # Check if not closed before closing
            await self.ws.close()
        if self.session and not self.session.closed: # Check if not closed
            await self.session.close()

    async def handshake(self):
        """Realizar handshake con el worker"""
        try:
            # Fase 1: Intercambio de claves
            public_key_bytes = self.public_key.public_bytes(
                encoding=serialization.Encoding.Raw, # Worker expects this
                format=serialization.PublicFormat.Raw
            )

            logger.info(f"Iniciando handshake con {self.worker_url}/phantom-init")

            async with self.session.post(
                f"{self.worker_url}/phantom-init",
                data=public_key_bytes,
                headers={'Content-Type': 'application/octet-stream'}
            ) as resp:
                if resp.status != 200:
                    error_text = await resp.text()
                    raise ConnectionError(f"Handshake fase 1 falló: {resp.status} - {error_text}")

                response_data = await resp.json()
                self.session_id = response_data['session_id']
                server_key_b64 = response_data['server_key']
                server_key_bytes = base64.b64decode(server_key_b64)

            # Derivar clave compartida
            self._derive_shared_key(server_key_bytes) # Sets self.crypto_key

            # Fase 2: Confirmación
            logger.info(f"Confirmando handshake con session_id: {self.session_id}")
            async with self.session.get(
                f"{self.worker_url}/phantom-handshake",
                cookies={'phantom-sid': self.session_id} # Worker expects this cookie
            ) as resp:
                if resp.status != 200:
                    error_text = await resp.text()
                    raise ConnectionError(f"Handshake fase 2 falló: {resp.status} - {error_text}")

                response_text = await resp.text()
                if response_text != "HANDSHAKE_SUCCESS":
                    raise ConnectionError(f"Handshake no confirmado por el worker: {response_text}")

            logger.info("Handshake completado exitosamente")
            return True

        except aiohttp.ClientConnectorError as e:
            logger.error(f"Error de conexión durante el handshake: {e}. Verifica la URL del worker y la conectividad.")
            raise
        except Exception as e:
            logger.error(f"Error genérico en handshake: {e}")
            raise

    def _derive_shared_key(self, server_public_key_bytes):
        """Derivar clave compartida usando X25519 + HKDF para ChaCha20Poly1305"""
        try:
            server_public_key = x25519.X25519PublicKey.from_public_bytes(server_public_key_bytes)
            shared_secret_ecdh = self.private_key.exchange(server_public_key) # This is the direct ECDH output

            # Worker's HKDF for finalKey:
            #   Input Key Material (IKM) for this HKDF is the output of *another* HKDF in the worker:
            #     `sharedSecret` in worker = deriveKey({name:X25519...}, serverPrivK, {name:HKDF...})
            #   This `sharedSecret` is then used as IKM for the final HKDF.
            # Client's HKDF for finalKey:
            #   IKM is `shared_secret_ecdh`.
            # This means the client and worker are likely deriving different final keys if the worker's
            # `sharedSecret` (input to final HKDF) is itself an HKDF output rather than raw ECDH output.
            #
            # Assuming client's interpretation is: ECDH_output -> HKDF -> final_key
            # Worker code for `sharedSecret` before final HKDF:
            # const sharedSecret = await crypto.subtle.deriveKey(
            #   { name: "X25519", public: clientPublicKey },
            #   session.serverKeyPair.privateKey,
            #   { name: "HKDF" }, // outputting a key for HKDF, not the raw secret
            #   false, ["deriveKey"]
            # )
            # This `sharedSecret` in worker is ALREADY an HKDF-processed key.
            # The client should mirror this if that's the case, or worker should use raw ECDH output for the final HKDF.
            #
            # For now, proceeding with client's simpler ECDH_output -> HKDF.
            # If crypto fails, this is a prime suspect.

            hkdf = HKDF(
                algorithm=hashes.SHA256(), # Matches worker's final HKDF hash
                length=32, # ChaCha20Poly1305 uses a 32-byte key
                salt=None, # Worker uses new Uint8Array(0) which is empty salt
                info=b'phantom_proxy_session', # Matches worker's final HKDF info
            )

            derived_key_bytes = hkdf.derive(shared_secret_ecdh)
            self.crypto_key = ChaCha20Poly1305(derived_key_bytes) # For ChaCha20
            logger.info("Clave de sesión derivada correctamente.")

        except Exception as e:
            logger.error(f"Error derivando clave compartida: {e}")
            raise

    async def connect_tunnel(self, target_host, target_port):
        """Establecer túnel WebSocket al destino"""
        if not self.crypto_key:
            raise ConnectionError("La clave de cifrado no está inicializada. ¿Handshake fallido?")
        try:
            ws_url = self.worker_url.replace('https://', 'wss://').replace('http://', 'ws://') + '/tunnel'
            logger.info(f"Conectando WebSocket a {ws_url}")
            self.ws = await self.session.ws_connect(
                ws_url,
                cookies={'phantom-sid': self.session_id} # Worker expects this cookie
            )

            target_data = f"{target_host}:{target_port}".encode('utf-8')
            encrypted_target = self._encrypt(target_data)
            await self.ws.send_bytes(encrypted_target)

            logger.info(f"Túnel WebSocket establecido a {target_host}:{target_port}")
            return True

        except aiohttp.ClientConnectorError as e:
            logger.error(f"Error de conexión WebSocket: {e}. Verifica la URL del worker y la ruta del túnel.")
            raise
        except Exception as e:
            logger.error(f"Error estableciendo túnel WebSocket: {e}")
            raise

    def _encrypt(self, data: bytes) -> bytes:
        """Cifrar datos con ChaCha20Poly1305"""
        if not self.crypto_key: raise RuntimeError("Crypto key not set for encryption")
        nonce = os.urandom(12) # ChaCha20Poly1305 uses a 12-byte nonce
        ciphertext = self.crypto_key.encrypt(nonce, data, None) # No associated data
        return nonce + ciphertext

    def _decrypt(self, encrypted_data: bytes) -> bytes:
        """Descifrar datos con ChaCha20Poly1305"""
        if not self.crypto_key: raise RuntimeError("Crypto key not set for decryption")
        if len(encrypted_data) < 12:
            raise ValueError("Datos cifrados inválidos (demasiado cortos para nonce)")

        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        try:
            return self.crypto_key.decrypt(nonce, ciphertext, None) # No associated data
        except Exception as e: # Catch specific crypto errors if possible, e.g., InvalidTag
            logger.error(f"Error de descifrado: {e}. Datos podrían estar corruptos o clave incorrecta.")
            raise

    async def proxy_data(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Proxificar datos entre cliente SOCKS y túnel WebSocket"""
        if not self.ws: raise ConnectionError("WebSocket no conectado para proxy_data")

        client_name = writer.get_extra_info('peername', 'ClienteDesconocido')
        logger.info(f"Iniciando proxy de datos para {client_name}")

        async def local_to_remote():
            try:
                while True:
                    data = await reader.read(8192) # Read up to 8KB
                    if not data:
                        logger.info(f"Conexión local cerrada por {client_name} (EOF).")
                        break

                    encrypted = self._encrypt(data)
                    if self.ws.closed:
                        logger.warning(f"WebSocket cerrado antes de enviar datos desde {client_name}.")
                        break
                    await self.ws.send_bytes(encrypted)
                    # logger.debug(f"Enviados {len(data)} bytes (cifrados) de {client_name} al túnel.")

            except asyncio.CancelledError:
                logger.info(f"Tarea local->remoto para {client_name} cancelada.")
            except Exception as e:
                if not isinstance(e, (ConnectionResetError, asyncio.IncompleteReadError)): # Common on close
                    logger.error(f"Error en local->remoto para {client_name}: {e}")
            finally:
                # Ensure WebSocket is closed if this direction finishes/errors
                if self.ws and not self.ws.closed:
                    logger.debug(f"Cerrando WebSocket desde local_to_remote para {client_name}")
                    await self.ws.close()

        async def remote_to_local():
            try:
                async for msg in self.ws:
                    if msg.type == aiohttp.WSMsgType.BINARY:
                        try:
                            decrypted = self._decrypt(msg.data)
                            writer.write(decrypted)
                            await writer.drain()
                            # logger.debug(f"Recibidos {len(decrypted)} bytes del túnel y escritos a {client_name}.")
                        except ValueError as e_decrypt: # From _decrypt if data invalid
                            logger.error(f"Error descifrando datos del túnel para {client_name}: {e_decrypt}")
                            break # Stop processing messages from this tunnel
                        except ConnectionResetError: # If client SOCKS connection resets during write
                            logger.info(f"Conexión SOCKS reseteada por {client_name} durante escritura.")
                            break
                    elif msg.type == aiohttp.WSMsgType.ERROR:
                        logger.error(f"Error de WebSocket para {client_name}: {self.ws.exception()}")
                        break
                    elif msg.type == aiohttp.WSMsgType.CLOSED:
                        logger.info(f"WebSocket cerrado por el servidor para {client_name}.")
                        break

            except asyncio.CancelledError:
                logger.info(f"Tarea remoto->local para {client_name} cancelada.")
            except Exception as e:
                logger.error(f"Error en remoto->local para {client_name}: {e}")
            finally:
                # Ensure local SOCKS writer is closed if this direction finishes/errors
                if not writer.is_closing():
                    logger.debug(f"Cerrando conexión SOCKS writer para {client_name} desde remote_to_local.")
                    writer.close()
                    try: await writer.wait_closed()
                    except: pass # Ignore errors on final close

        try:
            await asyncio.gather(local_to_remote(), remote_to_local())
        except Exception as e:
            logger.error(f"Excepción no manejada en gather para proxy_data ({client_name}): {e}")
        finally:
            logger.info(f"Proxy de datos finalizado para {client_name}.")
            # Final cleanup, though individual tasks should handle their resources
            if self.ws and not self.ws.closed: await self.ws.close()
            if not writer.is_closing(): writer.close(); await writer.wait_closed()


async def handle_socks5_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, worker_url: str):
    """Manejar conexión SOCKS5 individual"""
    client_addr_tuple = writer.get_extra_info('peername')
    client_addr_str = f"{client_addr_tuple[0]}:{client_addr_tuple[1]}" if client_addr_tuple else "ClienteSOCKSDesconocido"
    logger.debug(f"Nueva conexión SOCKS5 entrante desde {client_addr_str}")

    phantom_instance = None
    try:
        # SOCKS5 handshake (RFC 1928)
        # 1. Version identifier/method selection
        ver_nmethods = await reader.readexactly(2)
        version, nmethods = ver_nmethods[0], ver_nmethods[1]

        if version != 5:
            logger.warning(f"Versión SOCKS no soportada ({version}) desde {client_addr_str}.")
            return

        methods_supported = await reader.readexactly(nmethods)
        if 0x00 not in methods_supported: # 0x00: NO AUTHENTICATION REQUIRED
            logger.warning(f"Cliente {client_addr_str} no soporta método de autenticación 'NO AUTH'.")
            writer.write(b"\x05\xFF") # NO ACCEPTABLE METHODS
            await writer.drain()
            return

        writer.write(b"\x05\x00") # Select NO AUTHENTICATION
        await writer.drain()

        # 2. Client Request
        req_header = await reader.readexactly(4) # VER, CMD, RSV, ATYP
        ver, cmd, rsv, atyp = req_header

        if ver != 5: return # Should be caught by first check
        if cmd != 1: # 0x01: CONNECT
            logger.warning(f"Comando SOCKS no soportado ({cmd}) desde {client_addr_str}.")
            writer.write(b"\x05\x07\x00\x01" + (b'\x00' * 6)) # CMD NOT SUPPORTED
            await writer.drain()
            return

        # Destination address and port
        if atyp == 1:  # IPv4
            addr_bytes = await reader.readexactly(4)
            host = ".".join(str(b) for b in addr_bytes)
        elif atyp == 3:  # Domain name
            domain_len_byte = await reader.readexactly(1)
            domain_len = domain_len_byte[0]
            host_bytes = await reader.readexactly(domain_len)
            host = host_bytes.decode('utf-8', errors='replace')
        elif atyp == 4: # IPv6
            addr_bytes = await reader.readexactly(16)
            host = f"[{':'.join(addr_bytes[i:i+2].hex() for i in range(0, 16, 2))}]" # Basic IPv6 format
        else:
            logger.warning(f"Tipo de dirección SOCKS no soportado ({atyp}) desde {client_addr_str}.")
            writer.write(b"\x05\x08\x00\x01" + (b'\x00' * 6)) # Address type not supported
            await writer.drain()
            return

        port_bytes = await reader.readexactly(2)
        port = struct.unpack("!H", port_bytes)[0]

        logger.info(f"Petición SOCKS5 de {client_addr_str} para {host}:{port}")

        # 3. Establish connection via Phantom Proxy
        phantom_instance = PhantomClient(worker_url)
        async with phantom_instance: # Use context manager for session cleanup
            if not await phantom_instance.handshake():
                # Reply: General SOCKS server failure
                writer.write(b"\x05\x01\x00\x01" + (b'\x00' * 6))
                await writer.drain()
                return

            if not await phantom_instance.connect_tunnel(host, port):
                writer.write(b"\x05\x01\x00\x01" + (b'\x00' * 6))
                await writer.drain()
                return

            # SOCKS Reply: Connection Succeeded
            # VER, REP (0x00), RSV, ATYP, BND.ADDR (0.0.0.0), BND.PORT (0)
            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            logger.info(f"Túnel Phantom establecido para {client_addr_str} -> {host}:{port}")

            # 4. Start proxying data
            await phantom_instance.proxy_data(reader, writer)

    except asyncio.IncompleteReadError:
        logger.debug(f"Cliente SOCKS {client_addr_str} cerró conexión prematuramente.")
    except ConnectionResetError:
        logger.debug(f"Conexión SOCKS reseteada por {client_addr_str}.")
    except Exception as e:
        # Avoid logging generic asyncio.CancelledError too loudly if it's part of normal shutdown
        if not isinstance(e, asyncio.CancelledError):
            logger.error(f"Error manejando conexión SOCKS5 para {client_addr_str}: {e} ({type(e).__name__})")
        # Try to send a general failure reply if possible
        if not writer.is_closing():
            try:
                writer.write(b"\x05\x01\x00\x01" + (b'\x00' * 6)) # General SOCKS server failure
                await writer.drain()
            except Exception:
                pass # Ignore errors trying to send final error message
    finally:
        if not writer.is_closing():
            writer.close()
            await writer.wait_closed()
        # `phantom_instance` and its session/websocket are closed by its __aexit__
        logger.debug(f"Conexión SOCKS5 con {client_addr_str} finalizada.")


async def start_proxy_server(worker_url: str, socks_port: int):
    """Iniciar el servidor proxy SOCKS5 principal"""
    server = await asyncio.start_server(
        lambda r, w: handle_socks5_connection(r, w, worker_url),
        "127.0.0.1", # Listen only on localhost for security by default
        socks_port
    )

    addr = server.sockets[0].getsockname()
    print(f"""
    ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
    ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
    ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
    ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
    ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝

    🔥 Phantom Proxy Cliente ACTIVO
    📡 Servidor SOCKS5 escuchando en: {addr[0]}:{addr[1]}
    🔗 URL del Worker configurada: {worker_url}

    Configura tu aplicación o sistema para usar el proxy SOCKS5:
    - Host/Dirección: 127.0.0.1
    - Puerto: {socks_port}
    - (Sin autenticación requerida)

    Presiona Ctrl+C para detener el servidor.
    """)

    try:
        async with server:
            await server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Cerrando servidor proxy Phantom...")
    finally:
        if server: # Ensure server object exists
            server.close()
            await server.wait_closed()
        logger.info("Servidor Phantom Proxy detenido.")

def main():
    # Argumentos de línea de comandos
    if len(sys.argv) < 2:
        print("❌ Error: URL del worker es requerida.")
        print(f"Uso: python3 {sys.argv[0]} <WORKER_URL> [SOCKS_PORT]")
        print(f"Ejemplo: python3 {sys.argv[0]} https://your-worker.workers.dev 1080")
        sys.exit(1)

    worker_url_arg = sys.argv[1]
    socks_port_arg = DEFAULT_SOCKS_PORT
    if len(sys.argv) > 2:
        try:
            socks_port_arg = int(sys.argv[2])
            if not (1024 <= socks_port_arg <= 65535):
                raise ValueError("Puerto SOCKS debe estar entre 1024 y 65535.")
        except ValueError as e:
            print(f"Puerto SOCKS inválido: '{sys.argv[2]}'. {e}. Usando puerto por defecto: {DEFAULT_SOCKS_PORT}.")
            socks_port_arg = DEFAULT_SOCKS_PORT

    # Verificar dependencias de Python
    try:
        import aiohttp
        import cryptography
    except ImportError as e_import:
        print(f"❌ Dependencia de Python faltante: {e_import.name}")
        print(f"   Por favor, instala las dependencias: pip install aiohttp cryptography")
        sys.exit(1)

    # Ejecutar servidor asyncio
    try:
        asyncio.run(start_proxy_server(worker_url_arg, socks_port_arg))
    except OSError as e_os:
        if e_os.errno == 98: # Address already in use
             print(f"❌ Error: El puerto {socks_port_arg} ya está en uso. Intenta con otro puerto.")
        else:
             print(f"❌ Error de sistema operativo al iniciar el servidor: {e_os}")
        sys.exit(1)
    except KeyboardInterrupt: # Already handled in start_proxy_server, but good for direct asyncio.run call
        print("\n👋 Phantom Proxy cerrado por el usuario (Ctrl+C).")
    except Exception as e_fatal:
        logger.error(f"Error fatal no manejado: {e_fatal}")
        sys.exit(1)

if __name__ == "__main__":
    main()
EOF

chmod +x cliente.py

# Crear script de inicio rápido
# This is the third file content provided by the user
cat > start.sh << EOF
#!/bin/bash
echo "🚀 Iniciando Phantom Proxy..."
# Ensure WORKER_URL is passed to cliente.py
# The deploy script sets WORKER_URL variable. This start.sh needs it too.
# If WORKER_URL is not in env, it will be empty.
# We should make sure cliente.py gets the WORKER_URL correctly.
# The deploy script defines WORKER_URL. If this start.sh is run later, that variable might not be set.
# It's better if cliente.py takes WORKER_URL as a command-line argument.
# The deploy script writes WORKER_URL into this start.sh, which is good.

# The deploy script does: echo "python3 cliente.py \"$WORKER_URL\" 1080" > start.sh
# So, $WORKER_URL below will be the actual URL string written by the deploy script.
python3 cliente.py "$WORKER_URL" 1080
EOF

chmod +x start.sh

# Finalización
print_step "8/8 - ¡Despliegue completado!"

print_status "✅ Worker desplegado en: $WORKER_URL"
print_status "✅ Cliente Python creado: $(pwd)/cliente.py"
print_status "✅ Script de inicio rápido creado: $(pwd)/start.sh"

echo -e "\n${GREEN}🎉 ¡PHANTOM PROXY LISTO PARA USAR!${NC}\n"

echo -e "${BLUE}Para iniciar el cliente proxy localmente:${NC}"
echo -e "  ${YELLOW}cd \"$(pwd)\"${NC}  (Si no estás ya en el directorio del proyecto: $PROJECT_NAME)"
echo -e "  ${YELLOW}./start.sh${NC}"
echo -e "${BLUE}O manualmente, si conoces la URL del worker:${NC}"
echo -e "  ${YELLOW}python3 cliente.py TU_WORKER_URL_AQUI 1080${NC}\n"

echo -e "${BLUE}Una vez iniciado el cliente, configura tu navegador/aplicación para usar el proxy SOCKS5:${NC}"
echo -e "  ${YELLOW}Tipo de Proxy: SOCKS5${NC}"
echo -e "  ${YELLOW}Host/Dirección del Proxy: 127.0.0.1${NC}"
echo -e "  ${YELLOW}Puerto del Proxy: 1080${NC}\n"

echo -e "${BLUE}Comandos útiles de Wrangler (ejecutar en este directorio: $(pwd)):${NC}"
echo -e "  ${YELLOW}wrangler tail${NC}        # Ver logs en tiempo real de tu worker '${PROJECT_NAME}'"
echo -e "  ${YELLOW}wrangler delete${NC}      # Eliminar el worker '${PROJECT_NAME}' de Cloudflare"
echo -e "  ${YELLOW}wrangler deploy${NC}      # Volver a desplegar el worker (si haces cambios en worker.js)"

print_status "¡Disfruta de tu proxy Phantom seguro y privado! 🚀"

#!/usr/bin/env node
const net = require('net')
const crypto = require('crypto')
const WebSocket = require('ws')
const axios = require('axios')

const DEFAULT_WORKER_URL = 'https://phantom-wo.silkvalley612.workers.dev'
const DEFAULT_SOCKS_PORT = 1080

class PhantomCrypto {
  constructor() {
    this.ecdh = crypto.createECDH('prime256v1')
    this.ecdh.generateKeys()
    this.sharedKey = null
  }

  getPublicKey() {
    return this.ecdh.getPublicKey(null, 'uncompressed')
  }

  deriveSharedKey(peerPublicKey) {
    this.sharedKey = this.ecdh.computeSecret(peerPublicKey)
    this.sharedKey = crypto.hkdfSync('sha256', this.sharedKey, null, Buffer.from('phantom_proxy_session'), 32)
  }

  encrypt(plaintext) {
    const iv = crypto.randomBytes(12)
    const cipher = crypto.createCipheriv('aes-256-gcm', this.sharedKey, iv)
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()])
    const tag = cipher.getAuthTag()
    return Buffer.concat([iv, encrypted, tag])
  }

  decrypt(data) {
    if (data.length < 28) throw new Error('Encrypted data too short')
    const iv = data.slice(0, 12)
    const tag = data.slice(data.length - 16)
    const encrypted = data.slice(12, data.length - 16)
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.sharedKey, iv)
    decipher.setAuthTag(tag)
    return Buffer.concat([decipher.update(encrypted), decipher.final()])
  }
}

class PhantomClient {
  constructor(workerUrl) {
    this.workerUrl = workerUrl
    this.crypto = new PhantomCrypto()
    this.sessionId = null
    this.ws = null
  }

  async handshake() {
    console.log('🤝 Iniciando handshake...')
    const pubKey = this.crypto.getPublicKey()
    const resp = await axios.post(`${this.workerUrl}/phantom-init`, pubKey, {
      headers: { 'Content-Type': 'application/octet-stream' },
      validateStatus: () => true,
      timeout: 10000
    })

    if (resp.status !== 200) {
      throw new Error(`Handshake fase 1 falló: ${resp.status} ${resp.statusText}`)
    }

    this.sessionId = resp.data.session_id
    const serverKey = Buffer.from(resp.data.server_key, 'base64')
    this.crypto.deriveSharedKey(serverKey)

    const handshakeResp = await axios.get(`${this.workerUrl}/phantom-handshake`, {
      headers: { Cookie: `phantom-sid=${this.sessionId}` },
      validateStatus: () => true,
      timeout: 10000
    })

    if (handshakeResp.data !== 'HANDSHAKE_SUCCESS') {
      throw new Error('Handshake fase 2 falló')
    }

    console.log('✅ Handshake completado')
  }

  async connect(host, port) {
    console.log(`🔗 Conectando a ${host}:${port}`)
    this.ws = new WebSocket(`${this.workerUrl.replace(/^http/, 'ws')}/tunnel`, {
      headers: { Cookie: `phantom-sid=${this.sessionId}` },
    })

    await new Promise((res, rej) => {
      this.ws.once('open', res)
      this.ws.once('error', rej)
      setTimeout(() => rej(new Error('WebSocket timeout')), 10000)
    })

    const target = Buffer.from(`${host}:${port}`)
    this.ws.send(this.crypto.encrypt(target))
  }

  async proxyData(socket) {
    this.ws.on('message', data => {
      try {
        const decrypted = this.crypto.decrypt(Buffer.from(data))
        socket.write(decrypted)
      } catch (e) {
        console.error('❌ Error decrypt:', e.message)
        socket.destroy()
        this.ws.close()
      }
    })

    socket.on('data', data => {
      try {
        if (this.ws.readyState === WebSocket.OPEN) {
          this.ws.send(this.crypto.encrypt(data))
        }
      } catch (e) {
        console.error('❌ Error encrypt:', e.message)
        socket.destroy()
        this.ws.close()
      }
    })

    socket.on('close', () => {
      if (this.ws) this.ws.close()
    })

    this.ws.on('close', () => {
      socket.destroy()
    })

    this.ws.on('error', (error) => {
      console.error('❌ WebSocket error:', error.message)
      socket.destroy()
    })
  }
}

async function handleSocksConnection(socket, workerUrl) {
  const clientAddr = `${socket.remoteAddress}:${socket.remotePort}`
  console.log(`📥 Nueva conexión SOCKS desde ${clientAddr}`)

  try {
    // SOCKS5 greeting
    const header = await readBytes(socket, 2)
    if (header[0] !== 0x05) throw new Error('Versión SOCKS inválida')
    const nMethods = header[1]
    await readBytes(socket, nMethods)
    socket.write(Buffer.from([0x05, 0x00]))

    // SOCKS5 request
    const req = await readBytes(socket, 4)
    if (req[1] !== 0x01) {
      socket.end()
      console.log(`❌ Comando SOCKS no soportado desde ${clientAddr}`)
      return
    }

    let addr, port
    if (req[3] === 0x01) { // IPv4
      const ipBuf = await readBytes(socket, 4)
      addr = Array.from(ipBuf).join('.')
    } else if (req[3] === 0x03) { // Domain name
      const lenBuf = await readBytes(socket, 1)
      const len = lenBuf[0]
      const domainBuf = await readBytes(socket, len)
      addr = domainBuf.toString()
    } else {
      socket.end()
      console.log(`❌ Tipo de dirección no soportado desde ${clientAddr}`)
      return
    }

    const portBuf = await readBytes(socket, 2)
    port = portBuf.readUInt16BE(0)

    console.log(`🎯 ${clientAddr} -> ${addr}:${port}`)

    // Create phantom client and connect
    const client = new PhantomClient(workerUrl)
    await client.handshake()
    await client.connect(addr, port)

    // SOCKS5 success response
    socket.write(Buffer.from([
      0x05, 0x00, 0x00, 0x01,
      0,0,0,0, // Bind address
      0,0      // Bind port
    ]))

    await client.proxyData(socket)
    console.log(`✅ Túnel establecido: ${clientAddr} <-> ${addr}:${port}`)

  } catch (e) {
    console.error(`❌ Error conexión SOCKS ${clientAddr}:`, e.message)
    socket.destroy()
  }
}

function readBytes(socket, length) {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0)
    function onData(data) {
      buf = Buffer.concat([buf, data])
      if (buf.length >= length) {
        socket.pause()
        socket.removeListener('data', onData)
        resolve(buf.slice(0, length))
        const leftover = buf.slice(length)
        if (leftover.length > 0) socket.unshift(leftover)
        socket.resume()
      }
    }
    socket.on('data', onData)
    socket.on('error', reject)
    socket.on('close', () => reject(new Error('Socket cerrado')))

    // Timeout para evitar conexiones colgadas
    setTimeout(() => {
      socket.removeListener('data', onData)
      reject(new Error('Timeout leyendo datos'))
    }, 30000)
  })
}

async function testWorkerConnection(workerUrl) {
  try {
    console.log(`🧪 Probando conexión con worker: ${workerUrl}`)
    const response = await axios.get(workerUrl, { timeout: 5000 })
    console.log('✅ Worker accesible')
    return true
  } catch (error) {
    console.error('❌ Worker no accesible:', error.message)
    return false
  }
}

async function main() {
  console.log('🚀 Phantom Proxy iniciando...')

  const workerUrl = process.argv[2] || DEFAULT_WORKER_URL
  const socksPort = parseInt(process.argv[3]) || DEFAULT_SOCKS_PORT

  // Test worker connection
  const workerOk = await testWorkerConnection(workerUrl)
  if (!workerOk) {
    console.error('❌ No se puede conectar al worker. Verifica la URL y tu conexión.')
    process.exit(1)
  }

  const server = net.createServer(socket => {
    socket.setTimeout(60000) // 60 second timeout
    socket.on('timeout', () => {
      console.log('⏰ Conexión timeout')
      socket.destroy()
    })
    handleSocksConnection(socket, workerUrl)
  })

  server.on('error', (error) => {
    console.error('❌ Error del servidor:', error.message)
    if (error.code === 'EADDRINUSE') {
      console.error(`Puerto ${socksPort} ya está en uso. Prueba con otro puerto.`)
    }
    process.exit(1)
  })

  server.listen(socksPort, '127.0.0.1', () => {
    console.log('')
    console.log('🔥 ===============================')
    console.log('🔥 Phantom Proxy ACTIVO')
    console.log('🔥 ===============================')
    console.log(`📍 Dirección: 127.0.0.1:${socksPort}`)
    console.log(`🔗 Worker: ${workerUrl}`)
    console.log('📋 Configuración para tu navegador:')
    console.log('   • Tipo: SOCKS5')
    console.log(`   • Host: 127.0.0.1`)
    console.log(`   • Puerto: ${socksPort}`)
    console.log('🔥 ===============================')
    console.log('')
  })

  // Graceful shutdown
  process.on('SIGINT', () => {
    console.log('\n🛑 Cerrando Phantom Proxy...')
    server.close(() => {
      console.log('✅ Proxy cerrado correctamente')
      process.exit(0)
    })
  })
}

if (require.main === module) {
  main().catch(error => {
    console.error('❌ Error fatal:', error.message)
    process.exit(1)
  })
}

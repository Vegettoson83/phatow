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
    const pubKey = this.crypto.getPublicKey()
    const resp = await axios.post(`${this.workerUrl}/phantom-init`, pubKey, {
      headers: { 'Content-Type': 'application/octet-stream' },
      validateStatus: () => true,
    })
    if (resp.status !== 200) throw new Error('Handshake phase 1 failed')
    this.sessionId = resp.data.session_id
    const serverKey = Buffer.from(resp.data.server_key, 'base64')
    this.crypto.deriveSharedKey(serverKey)

    const handshakeResp = await axios.get(`${this.workerUrl}/phantom-handshake`, {
      headers: { Cookie: `phantom-sid=${this.sessionId}` },
      validateStatus: () => true,
    })
    if (handshakeResp.data !== 'HANDSHAKE_SUCCESS') throw new Error('Handshake phase 2 failed')
  }

  async connect(host, port) {
    this.ws = new WebSocket(`${this.workerUrl.replace(/^http/, 'ws')}/tunnel`, {
      headers: { Cookie: `phantom-sid=${this.sessionId}` },
    })

    await new Promise((res, rej) => {
      this.ws.once('open', res)
      this.ws.once('error', rej)
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
        console.error('Decrypt error:', e)
        socket.destroy()
        this.ws.close()
      }
    })

    socket.on('data', data => {
      try {
        this.ws.send(this.crypto.encrypt(data))
      } catch (e) {
        console.error('Encrypt error:', e)
        socket.destroy()
        this.ws.close()
      }
    })

    socket.on('close', () => this.ws.close())
    this.ws.on('close', () => socket.destroy())
  }
}

async function handleSocksConnection(socket, workerUrl) {
  try {
    const header = await readBytes(socket, 2)
    if (header[0] !== 0x05) throw new Error('Invalid SOCKS version')
    const nMethods = header[1]
    await readBytes(socket, nMethods)
    socket.write(Buffer.from([0x05, 0x00]))

    const req = await readBytes(socket, 4)
    if (req[1] !== 0x01) { socket.end(); return }

    let addr, port
    if (req[3] === 0x01) {
      const ipBuf = await readBytes(socket, 4)
      addr = Array.from(ipBuf).join('.')
    } else if (req[3] === 0x03) {
      const lenBuf = await readBytes(socket, 1)
      const len = lenBuf[0]
      const domainBuf = await readBytes(socket, len)
      addr = domainBuf.toString()
    } else {
      socket.end()
      return
    }
    const portBuf = await readBytes(socket, 2)
    port = portBuf.readUInt16BE(0)

    const client = new PhantomClient(workerUrl)
    await client.handshake()
    await client.connect(addr, port)

    socket.write(Buffer.from([
      0x05, 0x00, 0x00, 0x01,
      0,0,0,0,
      0,0
    ]))

    await client.proxyData(socket)
  } catch (e) {
    console.error('SOCKS connection error:', e)
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
    socket.on('close', () => reject(new Error('Socket closed')))
  })
}

async function main() {
  const workerUrl = process.argv[2] || DEFAULT_WORKER_URL
  const socksPort = parseInt(process.argv[3]) || DEFAULT_SOCKS_PORT

  const server = net.createServer(socket => handleSocksConnection(socket, workerUrl))

  server.listen(socksPort, '127.0.0.1', () => {
    console.log(`🔥 Phantom Proxy activo en 127.0.0.1:${socksPort}`)
    console.log(`🔗 Conectando a worker: ${workerUrl}`)
  })
}

main().catch(console.error)



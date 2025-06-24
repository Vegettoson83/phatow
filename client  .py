// phantom-client-socks5.js (Node.js compatible, downgraded to P-256)
import fetch from 'node-fetch';
import WebSocket from 'ws';
import net from 'net';
import { randomBytes } from 'crypto';
import { TextEncoder, TextDecoder } from 'util';
import { webcrypto } from 'crypto';

const crypto = webcrypto;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

const WORKER_URL = 'https://shadow.silkvalley612.workers.dev';
const LOCAL_PORT = 1080; // Local SOCKS5 proxy port

async function deriveKeyAndInitSession() {
  // Generate ECDH P-256 key pair
  const clientKeyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey']
  );

  // Export client's public key
  const clientPubRaw = new Uint8Array(
    await crypto.subtle.exportKey('raw', clientKeyPair.publicKey)
  );

  // Initiate phantom-init
  const initResp = await fetch(`${WORKER_URL}/phantom-init`, {
    method: 'POST',
    body: Buffer.from(clientPubRaw),
  });
  const { session_id, server_key } = await initResp.json();
  const cookie = initResp.headers.get('set-cookie');

  // Import server's public key
  const serverPubRaw = Uint8Array.from(Buffer.from(server_key, 'base64'));
  const serverPublicKey = await crypto.subtle.importKey(
    'raw',
    serverPubRaw,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );

  // Derive shared AES-GCM key
  const derivedKey = await crypto.subtle.deriveKey(
    { name: 'ECDH', public: serverPublicKey },
    clientKeyPair.privateKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  // Confirm handshake
  await fetch(`${WORKER_URL}/phantom-handshake`, {
    method: 'POST',
    headers: { Cookie: cookie }
  });

  return { derivedKey, cookie };
}

async function encryptMessage(derivedKey, data) {
  const iv = randomBytes(12);
  const encryptedBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    derivedKey,
    data
  );
  return Buffer.concat([iv, Buffer.from(encryptedBuffer)]);
}

async function decryptMessage(derivedKey, payload) {
  const iv = payload.slice(0, 12);
  const ciphertext = payload.slice(12);
  const decryptedBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    derivedKey,
    ciphertext
  );
  return Buffer.from(decryptedBuffer);
}

function startSocks5Proxy(derivedKey, cookie) {
  const server = net.createServer(socket => {
    const ws = new WebSocket(`${WORKER_URL.replace('https', 'wss')}/tunnel`, {
      headers: { Cookie: cookie }
    });

    ws.on('open', () => {
      socket.once('data', async data => {
        if (data[0] !== 0x05) return socket.destroy();
        socket.write(Buffer.from([0x05, 0x00]));

        socket.once('data', async req => {
          const addrType = req[3];
          let addr, port;

          if (addrType === 0x01) {
            addr = Array.from(req.slice(4, 8)).join('.');
            port = req.readUInt16BE(8);
          } else if (addrType === 0x03) {
            const len = req[4];
            addr = req.slice(5, 5 + len).toString();
            port = req.readUInt16BE(5 + len);
          } else {
            return socket.destroy();
          }

          const target = `${addr}:${port}`;
          const encryptedTarget = await encryptMessage(
            derivedKey,
            encoder.encode(target)
          );
          ws.send(encryptedTarget);

          socket.write(Buffer.from([
            0x05, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00
          ]));

          socket.on('data', async chunk => {
            ws.send(await encryptMessage(derivedKey, chunk));
          });
        });
      });
    });

    ws.on('message', async msg => {
      try {
        const plain = await decryptMessage(derivedKey, Buffer.from(msg));
        socket.write(plain);
      } catch (err) {
        console.error('[!] Decryption error:', err.message);
      }
    });

    ws.on('close', () => socket.destroy());
    socket.on('close', () => ws.close());
  });

  server.listen(LOCAL_PORT, () => {
    console.log(`[+] SOCKS5 proxy running on 127.0.0.1:${LOCAL_PORT}`);
  });
}

(async () => {
  const { derivedKey, cookie } = await deriveKeyAndInitSession();
  startSocks5Proxy(derivedKey, cookie);
})();


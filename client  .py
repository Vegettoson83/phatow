#!/usr/bin/env python3
# phantom_proxy.py - Plug & Play Stealth Proxy
import asyncio
import sys
import os
import base64
import struct
import aiohttp
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Configuración automática
DEFAULT_WORKER_URL = https://phantom-wo.brucewill945.workers.dev
DEFAULT_SOCKS_PORT = 1080

class PhantomClient:
    def __init__(self, worker_url):
        self.worker_url = worker_url
        self.session = aiohttp.ClientSession()
        self.crypto = self.PhantomCrypto()
        self.session_id = None
    
    class PhantomCrypto:
        def __init__(self):
            self.private_key = x25519.X25519PrivateKey.generate()
            self.public_key = self.private_key.public_key()
            self.shared_key = None
            self.chacha = None
        
        def derive_shared_key(self, peer_public_key_bytes):
            peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)
            shared_secret = self.private_key.exchange(peer_public_key)
            
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'phantom_proxy_session',
                backend=default_backend()
            )
            self.shared_key = hkdf.derive(shared_secret)
            self.chacha = ChaCha20Poly1305(self.shared_key)
    
    async def handshake(self):
        """Realiza el protocolo de enlace con el worker"""
        # Fase 1: Envía clave pública
        public_key_bytes = self.crypto.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        async with self.session.post(
            f"{self.worker_url}/phantom-init",
            data=public_key_bytes
        ) as resp:
            if resp.status != 200:
                raise ConnectionError("Handshake phase 1 failed")
            
            response = await resp.json()
            self.session_id = response['session_id']
            server_key = base64.b64decode(response['server_key'])
        
        # Fase 2: Confirmación
        self.crypto.derive_shared_key(server_key)
        async with self.session.get(
            f"{self.worker_url}/phantom-handshake",
            cookies={'phantom-sid': self.session_id}
        ) as resp:
            if await resp.text() != "HANDSHAKE_SUCCESS":
                raise ConnectionError("Handshake phase 2 failed")
    
    async def connect(self, host, port):
        """Establece conexión con el destino a través del túnel"""
        # Conectar via WebSocket
        self.ws = await self.session.ws_connect(
            f"{self.worker_url}/tunnel",
            cookies={'phantom-sid': self.session_id}
        )
        
        # Enviar destino cifrado
        target = f"{host}:{port}".encode()
        encrypted = self.crypto.chacha.encrypt(os.urandom(12), target, None)
        await self.ws.send_bytes(encrypted)
    
    def encrypt(self, data):
        """Cifra datos con nonce aleatorio"""
        nonce = os.urandom(12)
        return nonce + self.crypto.chacha.encrypt(nonce, data, None)
    
    def decrypt(self, data):
        """Descifra datos"""
        if len(data) < 12:
            raise ValueError("Datos cifrados inválidos")
        nonce = data[:12]
        ciphertext = data[12:]
        return self.crypto.chacha.decrypt(nonce, ciphertext, None)
    
    async def proxy_data(self, reader, writer):
        """Reenvía datos entre cliente SOCKS y túnel Phantom"""
        async def local_to_remote():
            try:
                while True:
                    data = await reader.read(4096)
                    if not data:
                        await self.ws.close()
                        break
                    encrypted = self.encrypt(data)
                    await self.ws.send_bytes(encrypted)
            except Exception as e:
                print("Local to remote error:", e)
            finally:
                await self.ws.close()
        
        async def remote_to_local():
            try:
                async for msg in self.ws:
                    if msg.type == aiohttp.WSMsgType.BINARY:
                        decrypted = self.decrypt(msg.data)
                        writer.write(decrypted)
                        await writer.drain()
            except Exception as e:
                print("Remote to local error:", e)
            finally:
                writer.close()
        
        await asyncio.gather(local_to_remote(), remote_to_local())

async def handle_socks5(reader, writer, worker_url):
    """Implementación básica de servidor SOCKS5"""
    # Autenticación
    await reader.read(2)  # Leer versión y número de métodos
    writer.write(b"\x05\x00")  # Sin autenticación
    await writer.drain()
    
    # Leer solicitud de conexión
    request = await reader.read(4)
    version, cmd, _, addr_type = request
    
    if cmd != 1:  # Solo soportamos CONNECT
        writer.close()
        return
    
    if addr_type == 1:  # IPv4
        host = ".".join(str(b) for b in await reader.read(4))
        port_bytes = await reader.read(2)
        port = struct.unpack("!H", port_bytes)[0]
    elif addr_type == 3:  # Nombre de dominio
        domain_length = (await reader.read(1))[0]
        host = (await reader.read(domain_length)).decode()
        port_bytes = await reader.read(2)
        port = struct.unpack("!H", port_bytes)[0]
    else:
        writer.close()
        return
    
    # Iniciar cliente Phantom
    client = PhantomClient(worker_url)
    try:
        await client.handshake()
        await client.connect(host, port)
    except Exception as e:
        print("Phantom connection failed:", e)
        writer.close()
        return
    
    # Confirmar conexión exitosa
    writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
    await writer.drain()
    
    # Iniciar proxy de datos
    await client.proxy_data(reader, writer)

async def main(worker_url, socks_port):
    server = await asyncio.start_server(
        lambda r, w: handle_socks5(r, w, worker_url),
        "127.0.0.1", socks_port
    )
    print(f"🔥 Phantom Proxy activo en 127.0.0.1:{socks_port}")
    print(f"🔗 Conectando a worker: {worker_url}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    worker_url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_WORKER_URL
    socks_port = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_SOCKS_PORT
    
    # Verificar dependencias
    try:
        import cryptography
    except ImportError:
        print("Instala las dependencias: pip install aiohttp cryptography")
        sys.exit(1)
    
    print("""
    ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
    ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
    ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
    ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
    ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
    Plug & Play Stealth Proxy v1.0
    """)
    asyncio.run(main(worker_url, socks_port))

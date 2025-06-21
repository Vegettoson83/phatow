#!/usr/bin/env python3
# phantom_proxy.py - VERSIÓN CORREGIDA
import asyncio
import sys
import os
import base64
import struct
import aiohttp
import json # Not used in this version, can be removed
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Configuración automática
DEFAULT_WORKER_URL = "https://your-worker.your-subdomain.workers.dev" # User needs to change this
DEFAULT_SOCKS_PORT = 1080

class PhantomClient:
    def __init__(self, worker_url):
        self.worker_url = worker_url
        self.session = None
        self.crypto = self.PhantomCrypto()
        self.session_id = None
        self.ws = None

    class PhantomCrypto:
        def __init__(self):
            # ✅ Usar P-256 en lugar de X25519
            self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            self.public_key = self.private_key.public_key()
            self.shared_key = None
            self.aesgcm = None

        def derive_shared_key(self, peer_public_key_bytes):
            try:
                # ✅ Importar clave pública P-256
                peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP256R1(), peer_public_key_bytes
                )

                # Derivar secreto compartido
                shared_secret = self.private_key.exchange(ec.ECDH(), peer_public_key)

                # ✅ Usar HKDF como en el worker
                hkdf = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=b'', # Consider using a salt if possible, even if static for this phase
                    info=b'phantom_proxy_session', # Ensure this matches worker
                    backend=default_backend()
                )
                self.shared_key = hkdf.derive(shared_secret)
                self.aesgcm = AESGCM(self.shared_key)
                print("✅ Clave compartida derivada correctamente")

            except Exception as e:
                print(f"❌ Error derivando clave: {e}")
                raise

    async def init_session(self):
        """Inicializa la sesión HTTP"""
        if not self.session or self.session.closed: # Check if session is closed
            timeout = aiohttp.ClientTimeout(total=30) # Consider making timeout configurable
            self.session = aiohttp.ClientSession(timeout=timeout)

    async def handshake(self):
        """Realiza el protocolo de enlace con el worker"""
        await self.init_session()

        try:
            # Fase 1: Envía clave pública
            public_key_bytes = self.crypto.public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )

            print(f"🔑 Enviando clave pública ({len(public_key_bytes)} bytes) a {self.worker_url}/phantom-init")

            async with self.session.post(
                f"{self.worker_url}/phantom-init",
                data=public_key_bytes,
                headers={'Content-Type': 'application/octet-stream'}
            ) as resp:
                if resp.status != 200:
                    text = await resp.text()
                    raise ConnectionError(f"Handshake phase 1 failed: {resp.status} - {text}")

                response_data = await resp.json() # Renamed for clarity
                self.session_id = response_data['session_id']
                server_key_b64 = response_data['server_key'] # Renamed for clarity
                server_key = base64.b64decode(server_key_b64)
                print(f"✅ Session ID recibido: {self.session_id}")
                print(f"🔑 Clave pública del servidor recibida ({len(server_key)} bytes)")

            # Fase 2: Derivar clave y confirmar
            self.crypto.derive_shared_key(server_key)

            print(f"🤝 Confirmando handshake con {self.worker_url}/phantom-handshake y session_id: {self.session_id}")
            async with self.session.get(
                f"{self.worker_url}/phantom-handshake",
                cookies={'phantom-sid': self.session_id} # Ensure worker expects cookie name 'phantom-sid'
            ) as resp:
                response_text = await resp.text()
                if resp.status != 200 or response_text != "HANDSHAKE_SUCCESS": # Check status too
                    raise ConnectionError(f"Handshake phase 2 failed: {resp.status} - {response_text}")

            print("✅ Handshake completado exitosamente")

        except aiohttp.ClientConnectorError as e:
            print(f"❌ Error de conexión en handshake: {e}. Verifica la URL del worker y la conectividad.")
            raise
        except Exception as e:
            print(f"❌ Error en handshake: {e}")
            raise

    async def connect(self, host, port):
        """Establece conexión con el destino a través del túnel"""
        await self.init_session() # Ensure session is active
        try:
            # Conectar via WebSocket
            ws_scheme = 'wss' if self.worker_url.startswith('https://') else 'ws'
            # Correctly form the base URL for WebSocket
            base_worker_url = self.worker_url.replace('https://', '').replace('http://', '')
            ws_url = f"{ws_scheme}://{base_worker_url}/tunnel"

            print(f"🌐 Conectando WebSocket a: {ws_url}")

            # Pass cookies for WebSocket connection if required by worker
            self.ws = await self.session.ws_connect(
                ws_url,
                cookies={'phantom-sid': self.session_id} # Ensure worker uses this for WS auth
            )

            print("✅ WebSocket conectado")

            # Enviar destino cifrado
            target = f"{host}:{port}".encode('utf-8')
            encrypted_target = self.encrypt(target) # Renamed for clarity
            await self.ws.send_bytes(encrypted_target)

            print(f"📡 Destino enviado al túnel: {host}:{port}")

        except aiohttp.ClientConnectorError as e:
            print(f"❌ Error de conexión WebSocket: {e}. Verifica la URL del worker y la ruta del túnel.")
            raise
        except Exception as e:
            print(f"❌ Error conectando al túnel: {e}")
            raise

    def encrypt(self, data):
        """Cifra datos con nonce aleatorio usando AES-GCM"""
        if not self.crypto.aesgcm:
            # This case should ideally be prevented by ensuring handshake is complete
            print("❌ Error: Intento de cifrar sin clave AESGCM. ¿Handshake completado?")
            raise ValueError("Criptografía no inicializada para cifrado.")

        nonce = os.urandom(12)  # 96 bits para AES-GCM
        ciphertext = self.crypto.aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext

    def decrypt(self, data):
        """Descifra datos usando AES-GCM"""
        if not self.crypto.aesgcm:
            print("❌ Error: Intento de descifrar sin clave AESGCM. ¿Handshake completado?")
            raise ValueError("Criptografía no inicializada para descifrado.")

        if len(data) < 12: # Nonce size
            print(f"❌ Error: Datos cifrados demasiado cortos para contener nonce ({len(data)} bytes)")
            raise ValueError("Datos cifrados inválidos (muy cortos)")

        nonce = data[:12]
        ciphertext = data[12:]
        try:
            return self.crypto.aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as e: # Catch specific crypto errors if possible
            print(f"❌ Error fatal descifrando datos: {e}. Podría ser una clave incorrecta o datos corruptos.")
            raise # Re-raise to be handled by caller

    async def proxy_data(self, reader, writer):
        """Reenvía datos entre cliente SOCKS y túnel Phantom"""
        print("🔄 Iniciando proxy de datos...")

        local_closed = asyncio.Event()
        remote_closed = asyncio.Event()

        async def local_to_remote():
            try:
                while not local_closed.is_set():
                    try:
                        data = await asyncio.wait_for(reader.read(4096), timeout=1.0)
                    except asyncio.TimeoutError:
                        if remote_closed.is_set(): break # If remote is also closed, exit
                        continue # Otherwise, just continue to allow remote_to_local to run

                    if not data:
                        print("📤 Cliente SOCKS cerró conexión (EOF)")
                        local_closed.set()
                        break

                    if self.ws is None or self.ws.closed:
                        print("❌ WebSocket no conectado o cerrado antes de enviar.")
                        local_closed.set()
                        break

                    encrypted = self.encrypt(data)
                    await self.ws.send_bytes(encrypted)
                    # print(f"📤 Enviados {len(data)} bytes al túnel")

            except asyncio.CancelledError:
                print("🛡️ Tarea local->remoto cancelada.")
            except Exception as e:
                print(f"❌ Error en local->remoto: {e} ({type(e)})")
            finally:
                local_closed.set()
                if self.ws and not self.ws.closed:
                    print("🚪 Cerrando WebSocket desde local_to_remote...")
                    await self.ws.close()
                print("🏁 Tarea local->remoto finalizada.")

        async def remote_to_local():
            try:
                while not remote_closed.is_set():
                    if self.ws is None or self.ws.closed:
                        if not local_closed.is_set(): # Only print if local isn't already closing
                            print("❌ WebSocket no conectado o cerrado al inicio de remote_to_local.")
                        remote_closed.set()
                        break

                    try:
                        msg = await asyncio.wait_for(self.ws.receive(), timeout=1.0)
                    except asyncio.TimeoutError:
                        if local_closed.is_set(): break # If local is also closed, exit
                        continue # Otherwise, just continue to allow local_to_remote to run

                    if msg.type == aiohttp.WSMsgType.BINARY:
                        try:
                            decrypted = self.decrypt(msg.data)
                            writer.write(decrypted)
                            await writer.drain()
                            # print(f"📥 Recibidos y escritos {len(decrypted)} bytes desde el túnel")
                        except ValueError as e: # Specific error from decrypt
                            print(f"❌ Error descifrando datos del túnel: {e}")
                            remote_closed.set()
                            break
                        except Exception as e: # Other write errors
                            print(f"❌ Error escribiendo al cliente SOCKS: {e}")
                            remote_closed.set()
                            break
                    elif msg.type == aiohttp.WSMsgType.CLOSED:
                        print("🚪 WebSocket cerrado por el servidor.")
                        remote_closed.set()
                        break
                    elif msg.type == aiohttp.WSMsgType.ERROR:
                        print(f"❌ Error de WebSocket: {self.ws.exception()}")
                        remote_closed.set()
                        break

            except asyncio.CancelledError:
                print("🛡️ Tarea remoto->local cancelada.")
            except Exception as e:
                print(f"❌ Error en remoto->local: {e} ({type(e)})")
            finally:
                remote_closed.set()
                if not writer.is_closing():
                    print("🚪 Cerrando writer desde remote_to_local...")
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception as e_close: print(f"Error en writer.wait_closed: {e_close}")

                print("🏁 Tarea remoto->local finalizada.")

        # Ejecutar ambas tareas concurrentemente
        try:
            await asyncio.gather(local_to_remote(), remote_to_local())
        except Exception as e:
            print(f"❌ Error crítico en proxy_data gather: {e}")
        finally:
            print("🔌 Conexión proxy (local SOCKS <-> túnel Phantom) cerrada.")
            # Ensure both sides are signaled if not already
            local_closed.set()
            remote_closed.set()
            # Final cleanup of resources
            if self.ws and not self.ws.closed: await self.ws.close()
            if not writer.is_closing(): writer.close(); await writer.wait_closed()

    async def close(self):
        """Cierra la sesión y el WebSocket"""
        print("Closing PhantomClient resources...")
        if self.ws and not self.ws.closed:
            await self.ws.close()
            print("WebSocket cerrado.")
        if self.session and not self.session.closed:
            await self.session.close()
            print("Sesión aiohttp cerrada.")
        self.ws = None
        self.session = None


async def handle_socks5(reader, writer, worker_url):
    """Implementación básica de servidor SOCKS5"""
    client_addr_tuple = writer.get_extra_info('peername')
    client_addr = f"{client_addr_tuple[0]}:{client_addr_tuple[1]}" if client_addr_tuple else "Desconocido"
    print(f"🔗 Nueva conexión SOCKS desde: {client_addr}")

    phantom_cli = None # Renamed for clarity

    try:
        # Fase de autenticación SOCKS5 (RFC 1928)
        # 1. Version identifier/method selection
        #    Client sends: VER (1 byte), NMETHODS (1 byte), METHODS (1 to 255 bytes)
        #    VER: 0x05 for SOCKS5
        #    NMETHODS: Number of method identifiers in METHODS
        #    METHODS: List of authentication methods supported by client
        version_nmethods = await reader.readexactly(2) # VER, NMETHODS
        version, nmethods = version_nmethods[0], version_nmethods[1]

        if version != 5:
            print(f"Unsupported SOCKS version: {version} from {client_addr}")
            return

        methods = await reader.readexactly(nmethods)
        # We support NO AUTHENTICATION REQUIRED (0x00)
        if 0x00 not in methods:
            print(f"Client {client_addr} does not support NO AUTHENTICATION method.")
            # Server selects NO ACCEPTABLE METHODS (0xFF)
            writer.write(b"\x05\xFF")
            await writer.drain()
            return

        # Server response: VER (1 byte), METHOD (1 byte)
        # METHOD: 0x00 for NO AUTHENTICATION
        writer.write(b"\x05\x00") # Select NO AUTHENTICATION
        await writer.drain()

        # 2. Client Request
        #    Client sends: VER (1 byte), CMD (1 byte), RSV (1 byte, 0x00), ATYP (1 byte), DST.ADDR, DST.PORT
        #    CMD: 0x01 for CONNECT
        #    ATYP: Address type: 0x01 (IPv4), 0x03 (Domain name), 0x04 (IPv6)
        req_header = await reader.readexactly(4) # VER, CMD, RSV, ATYP
        ver, cmd, rsv, atyp = req_header[0], req_header[1], req_header[2], req_header[3]

        if ver != 5: return # Should not happen if first phase passed
        if cmd != 1: # CMD_CONNECT
            print(f"Comando SOCKS no soportado: {cmd} desde {client_addr}")
            # Reply: command not supported
            writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            return

        # Process destination address based on ATYP
        if atyp == 1:  # IPv4
            addr_bytes = await reader.readexactly(4)
            host = ".".join(str(b) for b in addr_bytes)
        elif atyp == 3:  # Domain name
            domain_len_byte = await reader.readexactly(1)
            domain_len = domain_len_byte[0]
            host_bytes = await reader.readexactly(domain_len)
            host = host_bytes.decode('utf-8') # Assuming UTF-8, standard for domains
        elif atyp == 4: # IPv6
            addr_bytes = await reader.readexactly(16)
            # Basic IPv6 formatting, could be more robust
            host = ':'.join(addr_bytes[i:i+2].hex() for i in range(0, 16, 2))
        else:
            print(f"Tipo de dirección SOCKS no soportado: {atyp} desde {client_addr}")
            # Reply: address type not supported
            writer.write(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            return

        port_bytes = await reader.readexactly(2)
        port = struct.unpack("!H", port_bytes)[0]

        print(f"📡 Petición SOCKS de {client_addr} para conectar a: {host}:{port}")

        # Iniciar cliente Phantom y conectar al worker/túnel
        phantom_cli = PhantomClient(worker_url)
        await phantom_cli.handshake()
        await phantom_cli.connect(host, port) # This now connects the WebSocket

        # SOCKS Reply to client: Connection established
        # VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
        # REP: 0x00 succeeded
        # BND.ADDR/PORT can be 0.0.0.0:0 if not directly bound
        writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        await writer.drain()

        print(f"✅ Túnel Phantom establecido para {client_addr} -> {host}:{port}")

        # Iniciar proxy de datos bidireccional
        await phantom_cli.proxy_data(reader, writer)

    except ConnectionRefusedError:
        print(f"❌ Conexión SOCKS rechazada para {client_addr} (posiblemente worker no disponible).")
        if not writer.is_closing(): writer.write(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00") # Host unreachable
    except asyncio.exceptions.IncompleteReadError:
        print(f"🔌 Conexión SOCKS cerrada prematuramente por {client_addr}.")
    except Exception as e:
        print(f"❌ Error severo en handle_socks5 para {client_addr}: {e} ({type(e)})")
        # General failure reply if writer is still open
        if not writer.is_closing():
            try:
                writer.write(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00") # General SOCKS server failure
                await writer.drain()
            except Exception as e_write:
                print(f" Fallo al enviar error SOCKS: {e_write}")
    finally:
        print(f"🏁 Finalizando conexión SOCKS para {client_addr}.")
        if phantom_cli:
            await phantom_cli.close()
        if not writer.is_closing():
            writer.close()
            try:
                await writer.wait_closed()
            except Exception as e_close_final: print(f"Error en writer.wait_closed final: {e_close_final}")

async def main_server(worker_url, socks_port): # Renamed from main to avoid conflict if this were a module
    # Verificar URL del worker
    if not worker_url or not worker_url.startswith(('http://', 'https://')):
        print("❌ URL del worker inválida o no especificada. Debe comenzar con http:// o https://")
        print(f"   URL actual: '{worker_url}'")
        # Attempt to use DEFAULT_WORKER_URL if argument is bad but not empty
        if not worker_url and DEFAULT_WORKER_URL:
             print(f"   Intentando con URL por defecto: {DEFAULT_WORKER_URL}")
             worker_url = DEFAULT_WORKER_URL
        elif worker_url and not worker_url.startswith(('http://', 'https://')):
             print("   Por favor, corrige la URL o usa la opción por defecto si está configurada.")
             return # Exit if URL is malformed and no default is usable
        elif not worker_url and not DEFAULT_WORKER_URL:
             print("   No se proporcionó URL y no hay URL por defecto. Saliendo.")
             return



    try:
        # Pass worker_url to the handler lambda
        server = await asyncio.start_server(
            lambda r, w: handle_socks5(r, w, worker_url),
            "127.0.0.1", socks_port
        )

        addr = server.sockets[0].getsockname()
        print(f"🔥 Phantom Proxy SOCKS5 activo en {addr[0]}:{addr[1]}")
        print(f"🔗 Conectando a través del Worker URL: {worker_url}")
        print("📋 Para usar, configura tu aplicación con:")
        print(f"   - Tipo de Proxy: SOCKS5")
        print(f"   - Servidor Proxy: 127.0.0.1")
        print(f"   - Puerto Proxy: {socks_port}")
        print("   - Sin Autenticación (usuario/contraseña vacíos)")
        print("\n⚡ Presiona Ctrl+C para detener el servidor proxy.")

        async with server:
            await server.serve_forever()

    except OSError as e:
        if e.errno == 98: # Address already in use
            print(f"❌ Error: El puerto {socks_port} ya está en uso. Intenta con otro puerto.")
        else:
            print(f"❌ Error de OS iniciando servidor: {e}")
    except KeyboardInterrupt:
        print("\n🛑 Deteniendo servidor proxy Phantom...")
    except Exception as e:
        print(f"❌ Error inesperado en main_server: {e}")
    finally:
        print("👋 Servidor Phantom Proxy detenido.")


if __name__ == "__main__":
    print("""
    ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
    ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
    ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
    ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
    ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
    Plug & Play Stealth Proxy v2.0 - Client (FIXED & ENHANCED)
    """)

    # Argument parsing
    if len(sys.argv) > 1 and (sys.argv[1] == "-h" or sys.argv[1] == "--help"):
        print(f"Uso: {sys.argv[0]} [WORKER_URL] [SOCKS_PORT]")
        print(f"  WORKER_URL: URL completa de tu Phantom Worker (ej: {DEFAULT_WORKER_URL})")
        print(f"  SOCKS_PORT: Puerto local para el servidor SOCKS5 (ej: {DEFAULT_SOCKS_PORT})")
        sys.exit(0)

    # Get WORKER_URL from args or use default
    worker_url_arg = sys.argv[1] if len(sys.argv) > 1 else None
    if not worker_url_arg:
        if "YOUR_WORKER_URL_ENV_VAR" in os.environ: # Example for env var
            worker_url_arg = os.environ["YOUR_WORKER_URL_ENV_VAR"]
        elif DEFAULT_WORKER_URL == "https://your-worker.your-subdomain.workers.dev":
             print("⚠️  ADVERTENCIA: Usando URL de worker por defecto. ¡Debes cambiarla!")
             print("   Puedes pasarla como argumento o modificar DEFAULT_WORKER_URL en el script.")
        worker_url_arg = DEFAULT_WORKER_URL # Fallback to default even if it's the placeholder

    # Get SOCKS_PORT from args or use default, with validation
    socks_port_arg = DEFAULT_SOCKS_PORT
    if len(sys.argv) > 2:
        try:
            socks_port_arg = int(sys.argv[2])
            if not (1024 <= socks_port_arg <= 65535): # Common port range
                raise ValueError("El puerto SOCKS debe estar entre 1024 y 65535.")
        except ValueError as e:
            print(f"❌ Puerto SOCKS inválido: {sys.argv[2]}. {e}. Usando puerto por defecto: {DEFAULT_SOCKS_PORT}.")
            socks_port_arg = DEFAULT_SOCKS_PORT

    # Verify dependencies
    try:
        import cryptography
        import aiohttp
    except ImportError as e:
        print(f"❌ Error de importación: {e}.")
        print("   Asegúrate de tener las dependencias instaladas.")
        print("   Ejecuta: pip install aiohttp cryptography")
        sys.exit(1)

    # Run the main server function
    try:
        asyncio.run(main_server(worker_url_arg, socks_port_arg))
    except Exception as e:
        print(f"Error fatal al ejecutar asyncio.run: {e}")
        sys.exit(1)

const WebSocket = require('ws');
const net = require('net');

// Configuración
const LOCAL_PORT = 1081; // Puerto donde escuchará localmente
const REMOTE_TARGET = '127.0.0.1:1080'; // A lo que el Worker redirige
const WORKER_URL = `wss://cdn-font-fallback.workers.dev/?target=${REMOTE_TARGET}`;

const server = net.createServer(localSocket => {
  const ws = new WebSocket(WORKER_URL);

  ws.on('open', () => {
    // Local TCP -> WebSocket
    localSocket.on('data', chunk => ws.send(chunk));
    localSocket.on('end', () => ws.close());
  });

  // WebSocket -> Local TCP
  ws.on('message', chunk => localSocket.write(chunk));
  ws.on('close', () => localSocket.end());
  ws.on('error', () => localSocket.destroy());

  localSocket.on('error', () => ws.close());
});

server.listen(LOCAL_PORT, () => {
  console.log(`🔁 Tunnel listo en localhost:${LOCAL_PORT}`);
});


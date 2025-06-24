// client/index.js
import { SocksProxyAgent } from 'socks-proxy-agent';
import WebSocket from 'ws';
import net from 'net';
import crypto from 'crypto';

class PhantomClient {
  constructor(config) {
    this.config = config;
    this.ws = null;
    this.connections = new Map(); // sessionId → { clientSocket, remoteSocket }
    this.reconnectAttempts = 0;
    this.stats = {
      bytesSent: 0,
      bytesReceived: 0,
      connections: 0
    };
  }

  async start() {
    this.connectToWorker();
    this.startSocksServer();
    this.startTrafficCamouflage();
  }

  connectToWorker() {
    this.ws = new WebSocket(this.config.workerUrl, {
      headers: {
        'X-Phantom-Auth': crypto.createHmac('sha256', this.config.secret)
          .update(Date.now().toString())
          .digest('hex')
      }
    });

    this.ws.on('open', () => {
      this.reconnectAttempts = 0;
      console.log('🔥 Conectado al Phantom Worker');
    });

    this.ws.on('message', this.handleWorkerMessage.bind(this));

    this.ws.on('close', () => {
      console.log(`⏳ Reconectando en ${Math.min(30, ++this.reconnectAttempts)}s...`);
      setTimeout(() => this.connectToWorker(), this.reconnectAttempts * 1000);
    });
  }

  handleWorkerMessage(data) {
    const message = JSON.parse(data);

    switch (message.type) {
      case 'data':
        this.handleDataMessage(message);
        break;
      case 'metrics':
        this.handleMetrics(message);
        break;
      case 'switch-endpoint':
        this.switchEndpoint(message);
        break;
    }
  }

  handleDataMessage({ sessionId, data }) {
    const conn = this.connections.get(sessionId);
    if (conn && conn.clientSocket.writable) {
      conn.clientSocket.write(Buffer.from(data, 'base64'));
      this.stats.bytesReceived += data.length;
    }
  }

  startSocksServer() {
    const server = net.createServer(socket => {
      const sessionId = crypto.randomBytes(8).toString('hex');
      this.connections.set(sessionId, { clientSocket: socket });
      this.stats.connections++;

      socket.on('data', data => {
        this.stats.bytesSent += data.length;
        this.ws.send(JSON.stringify({
          type: 'data',
          sessionId,
          data: data.toString('base64')
        }));
      });

      socket.on('end', () => {
        this.ws.send(JSON.stringify({ type: 'close', sessionId }));
        this.connections.delete(sessionId);
      });

      socket.on('error', () => this.connections.delete(sessionId));
    });

    server.listen(this.config.socksPort, '127.0.0.1', () => {
      console.log(`🔌 SOCKS5 escuchando en 127.0.0.1:${this.config.socksPort}`);
    });
  }

  startTrafficCamouflage() {
    // Genera tráfico legítimo para camuflar actividad
    setInterval(() => {
      fetch('https://www.google.com/analytics', {
        method: 'POST',
        body: JSON.stringify({
          events: [{
            name: `pageview_${crypto.randomBytes(2).toString('hex')}`,
            params: {
              engagement_time: Math.floor(Math.random() * 10),
              session_id: `session_${Date.now()}`
            }
          }]
        })
      }).catch(() => {});
    }, 15000);
  }
}

// Configuración dinámica
const config = {
  workerUrl: 'wss://phantom-gateway.your-worker.workers.dev',
  secret: process.env.PHANTOM_SECRET,
  socksPort: 1080
};

const client = new PhantomClient(config);
client.start();

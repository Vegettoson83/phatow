// backend/index.js
import net from 'net';
import { SocksProxyAgent } from 'socks-proxy-agent';
import { createBrotliCompress, createBrotliDecompress } from 'zlib';
import crypto from 'crypto';

class PhantomBackend {
  constructor() {
    this.connections = new Map();
    this.metrics = {
      connections: 0,
      bytesTransferred: 0,
      errorCount: 0
    };
  }

  start(port = 3000) {
    this.server = net.createServer(socket => {
      const connectionId = crypto.randomBytes(4).toString('hex');
      this.connections.set(connectionId, { socket });
      this.metrics.connections++;

      let targetSocket = null;
      let buffer = [];
      let host = '';
      let targetPort = 0; // Renamed to avoid conflict with the port argument of start()
      let compression = null;
      let decompression = null; // Added for symmetry

      const setupConnection = () => {
        try {
          // Usar proxy si está configurado
          const agent = process.env.EXTERNAL_PROXY
            ? new SocksProxyAgent(process.env.EXTERNAL_PROXY)
            : null;

          targetSocket = net.connect({
            host,
            port: targetPort, // Use the renamed variable
            agent,
            servername: host // SNI para TLS
          });

          targetSocket.on('connect', () => {
            // Vaciar buffer
            while (buffer.length) {
              const chunk = buffer.shift();
              targetSocket.write(compression ?
                compression.write(chunk) : chunk);
            }
            // If compression is active, ensure any buffered compressed data is flushed
            if (compression) {
                compression.flush();
            }
          });

          // Pipe bidireccional con compresión opcional
          if (compression && decompression) {
            socket.pipe(compression).pipe(targetSocket);
            targetSocket.pipe(decompression).pipe(socket);
          } else {
            socket.pipe(targetSocket);
            targetSocket.pipe(socket);
          }

          targetSocket.on('data', data => {
            this.metrics.bytesTransferred += data.length;
          });

          targetSocket.on('error', handleError);
          targetSocket.on('end', () => { // Handle target socket closing
            socket.end();
            this.connections.delete(connectionId);
          });
        } catch (err) {
          handleError(err);
        }
      };

      const handleError = (err) => {
        this.metrics.errorCount++;
        console.error(`Error on connection ${connectionId} to ${host}:${targetPort}:`, err.message);
        socket.end();
        targetSocket?.destroy(); // Use destroy to ensure no more I/O
        this.connections.delete(connectionId);
      };

      socket.on('data', data => {
        // Primera línea: "host:port[:compression]\n"
        if (!targetSocket) {
          const headerEnd = data.indexOf('\n');
          if (headerEnd === -1) {
            buffer.push(data); // Buffer data if header is not complete
            return;
          }

          const completeData = Buffer.concat([...buffer, data]); // Concatenate buffered parts with new data
          const headerPart = completeData.subarray(0, completeData.indexOf('\n'));
          const bodyPart = completeData.subarray(completeData.indexOf('\n') + 1);

          buffer = []; // Clear buffer

          const header = headerPart.toString();
          const parts = header.split(':');
          host = parts[0];
          targetPort = parseInt(parts[1], 10); // Parse port to integer
          const compressionType = parts[2];

          if (compressionType === 'br') {
            compression = createBrotliCompress();
            decompression = createBrotliDecompress();
          }

          if (host && targetPort) { // Ensure host and port are valid
             setupConnection();
             if (bodyPart.length > 0) { // If there's data after header, process it
                if (targetSocket && targetSocket.writable) {
                    targetSocket.write(compression ? compression.write(bodyPart) : bodyPart);
                    if (compression) compression.flush();
                } else {
                    // If targetSocket is not ready, buffer this initial body part
                    // This case should ideally be handled by the 'connect' event logic for targetSocket
                    buffer.push(bodyPart);
                }
             }
          } else {
            console.error("Invalid header format:", header);
            socket.end();
            return;
          }

        } else {
            if (targetSocket.writable) {
                 targetSocket.write(compression ? compression.write(data) : data);
                 if (compression) compression.flush();
            }
        }
      });

      socket.on('end', () => {
        targetSocket?.end();
        this.connections.delete(connectionId);
      });
      socket.on('error', handleError);
    });

    this.server.listen(port, () => {
      console.log(`🚀 Phantom Backend escuchando en puerto ${port}`);
    });

    // Reportar métricas
    setInterval(() => this.reportMetrics(), 30000);
  }

  reportMetrics() {
    // Enviar métricas a sistema de monitoreo
    console.log('📊 Métricas:', JSON.stringify(this.metrics));
    // Reset parcial
    this.metrics.bytesTransferred = 0;
    // Reset connections count based on active connections, or reset periodically as needed
    this.metrics.connections = this.connections.size;
    // errorCount might be reset or accumulated based on monitoring strategy
  }
}

const backend = new PhantomBackend();
backend.start(process.env.PORT || 3000);

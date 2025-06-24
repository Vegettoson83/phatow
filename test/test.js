const net = require('net')

async function testSocksProxy() {
  console.log('🧪 Probando conexión SOCKS...')

  return new Promise((resolve, reject) => {
    const socket = net.createConnection(1080, '127.0.0.1')

    socket.on('connect', () => {
      console.log('✅ Conexión SOCKS establecida')
      socket.end()
      resolve(true)
    })

    socket.on('error', (error) => {
      console.log('❌ Error conexión SOCKS:', error.code)
      resolve(false)
    })

    setTimeout(() => {
      socket.destroy()
      console.log('⏰ Timeout - ¿Está el proxy ejecutándose?')
      resolve(false)
    }, 5000)
  })
}

async function main() {
  console.log('Phantom Proxy - Tests')
  console.log('====================')

  const result = await testSocksProxy()
  process.exit(result ? 0 : 1)
}

if (require.main === module) {
  main()
}

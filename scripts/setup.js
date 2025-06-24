#!/usr/bin/env node

const fs = require('fs')
const path = require('path')
const { execSync } = require('child_process')

console.log('🚀 Configuración automática de Phantom Proxy')
console.log('================================================')

// Check if Node.js version is compatible
const nodeVersion = process.version
const majorVersion = parseInt(nodeVersion.slice(1).split('.')[0])

if (majorVersion < 18) {
  console.error('❌ Node.js 18 o superior requerido')
  console.error(`   Versión actual: ${nodeVersion}`)
  process.exit(1)
}

console.log(`✅ Node.js ${nodeVersion} detectado`)

// Check if package.json exists
if (!fs.existsSync('package.json')) {
  console.error('❌ package.json no encontrado')
  console.error('   Ejecuta este script desde el directorio raíz del proyecto')
  process.exit(1)
}

// Install dependencies
console.log('\n📦 Instalando dependencias...')
try {
  execSync('npm install', { stdio: 'inherit' })
  console.log('✅ Dependencias instaladas')
} catch (error) {
  console.error('❌ Error instalando dependencias:', error.message)
  process.exit(1)
}

// Check if wrangler is available
console.log('\n🔧 Verificando Wrangler...')
try {
  execSync('npx wrangler --version', { stdio: 'pipe' })
  console.log('✅ Wrangler disponible')
} catch (error) {
  console.log('⚠️  Instalando Wrangler...')
  try {
    execSync('npm install -g wrangler', { stdio: 'inherit' })
    console.log('✅ Wrangler instalado')
  } catch (installError) {
    console.error('❌ Error instalando Wrangler:', installError.message)
    process.exit(1)
  }
}

// Create directories if they don't exist
const dirs = ['scripts', 'test', 'logs']
dirs.forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true })
    console.log(`📁 Directorio creado: ${dir}`)
  }
})

// Create .gitignore if it doesn't exist
if (!fs.existsSync('.gitignore')) {
  const gitignore = `
# Dependencies
node_modules/
package-lock.json

# Logs
logs/
*.log

# Environment files
.env
.env.local

# Wrangler
.wrangler/

# OS files
.DS_Store
Thumbs.db
`
  fs.writeFileSync('.gitignore', gitignore.trim())
  console.log('📝 .gitignore creado')
}

// Create test file
const testFile = path.join('test', 'test.js')
if (!fs.existsSync(testFile)) {
  const testContent = `
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
`
  fs.writeFileSync(testFile, testContent.trim())
  console.log('🧪 Archivo de test creado')
}

// Create start script
const startScript = path.join('scripts', 'start.js')
if (!fs.existsSync(startScript)) {
  const startContent = `
#!/

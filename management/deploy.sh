#!/bin/bash
# management/deploy.sh - Versión Automatizada Mejorada

set -e # Exit immediately if a command exits with a non-zero status.

DEPLOY_LOG="phantom_deploy.log"
CLOUDFLARE_DIR="orchestrator/cloudflare"
CLIENT_CONFIG_DIR="client" # Define client directory
CLIENT_CONFIG_FILE="${CLIENT_CONFIG_DIR}/config.json" # Define full path for client config
CLIENT_GENERATED_CONFIG_FILE="${CLIENT_CONFIG_DIR}/config_generated.json" # Define full path for generated config

echo "🔐 Autenticando en servicios..."
# Aquí asume que vault está configurado correctamente y accesible.
# Consider adding a check if vault CLI is installed.
if ! command -v vault &> /dev/null; then
    echo "❌ vault CLI no encontrado. Por favor, instálalo y configúralo."
    exit 1
fi
export CLOUDFLARE_API_TOKEN=$(vault read -field=token cloudflare/creds)
# Add error check for vault read
if [ -z "$CLOUDFLARE_API_TOKEN" ]; then
    echo "❌ No se pudo obtener CLOUDFLARE_API_TOKEN de Vault. Verifica la configuración de Vault."
    exit 1
fi
export FASTLY_API_KEY=$(vault read -field=key fastly/creds)
if [ -z "$FASTLY_API_KEY" ]; then
    echo "❌ No se pudo obtener FASTLY_API_KEY de Vault. Verifica la configuración de Vault."
    # This might not be critical if Fastly deployment is optional or handled later.
    # For now, we'll let it proceed but a stricter script might exit.
    echo "⚠️  Continuando sin FASTLY_API_KEY."
fi
echo "Autenticación (Cloudflare y Fastly vía Vault) completada."

if [ ! -d "$CLOUDFLARE_DIR" ]; then
  echo "❌ No se encontró el directorio del worker de Cloudflare: $CLOUDFLARE_DIR"
  exit 1
fi

# Create client directory if it doesn't exist, for config files
if [ ! -d "$CLIENT_CONFIG_DIR" ]; then
  echo "📁 Creando directorio de cliente: $CLIENT_CONFIG_DIR"
  mkdir -p "$CLIENT_CONFIG_DIR"
fi

# Check for wrangler.toml and create a basic one if not found
WRANGLER_TOML_PATH="${CLOUDFLARE_DIR}/wrangler.toml"
if [ ! -f "$WRANGLER_TOML_PATH" ]; then
  echo "⚠️ No se encontró $WRANGLER_TOML_PATH, creando uno básico..."
  # Use current date for compatibility_date as per original script's intention
  CURRENT_DATE=$(date +%Y-%m-%d)
  cat > "$WRANGLER_TOML_PATH" <<EOF
name = "phantom-worker"
main = "worker.js" # Assumes worker.js is directly in CLOUDFLARE_DIR
compatibility_date = "$CURRENT_DATE"
usage_model = "bundled" # 'bundled' is a common usage model
workers_dev = true # Enables wrangler dev features, good default
EOF
  echo "$WRANGLER_TOML_PATH creado."
fi

echo "🚀 Desplegando Worker en Cloudflare desde el directorio: $CLOUDFLARE_DIR..."
# Navigate to Cloudflare worker directory to run wrangler commands
# Storing current directory to return later
ORIGINAL_DIR=$(pwd)
cd "$CLOUDFLARE_DIR"

# Check if wrangler CLI is installed
if ! command -v wrangler &> /dev/null; then
  echo "❌ wrangler CLI no está instalado. Por favor, instálalo (ej: npm install -g wrangler o yarn global add wrangler)."
  cd "$ORIGINAL_DIR" # Return to original directory before exiting
  exit 1
fi

# Attempt to deploy the worker, redirecting output to a log file in the project root
# Log path needs to be relative to where the script is, or absolute.
# Assuming DEPLOY_LOG is in the project root, adjust path from CLOUDFLARE_DIR
DEPLOY_LOG_PATH="${ORIGINAL_DIR}/${DEPLOY_LOG}"
echo "📜 El log de despliegue se guardará en: $DEPLOY_LOG_PATH"
if ! wrangler deploy > "$DEPLOY_LOG_PATH" 2>&1; then
  echo "❌ Error en el despliegue de Cloudflare. Revisa el log para más detalles:"
  tail -n 20 "$DEPLOY_LOG_PATH" # Show last 20 lines of the log
  cd "$ORIGINAL_DIR" # Return to original directory
  exit 1
fi

echo "✅ Despliegue del Worker de Cloudflare completado."

echo "🔄 Obteniendo endpoint del Worker desplegado..."
# wrangler info might not be available or might change format.
# wrangler dev often gives a URL. `wrangler deployments view` is more robust for deployed workers.
# For simplicity, using `wrangler deployments list` and picking the latest active one.
# This part can be fragile.
# Alternative: `wrangler whoami` to get account_id, then construct expected URL or use API.
# For now, let's try to parse `wrangler deployments list` output if `wrangler info` is problematic.
# The provided script used `wrangler info | grep ...`, which is okay if `info` provides a clear URL.
ENDPOINT=$(wrangler info | grep 'https://' | head -n 1 | tr -d '\r\n' | sed 's/ *$//') # Clean potential trailing spaces

if [ -z "$ENDPOINT" ]; then
  echo "⚠️ No se pudo obtener el endpoint automáticamente usando 'wrangler info'."
  echo "   Intenta configurar ${ORIGINAL_DIR}/${CLIENT_CONFIG_FILE} manualmente."
  # Attempt to find from deployments list as a fallback
  LATEST_DEPLOYMENT_URL=$(wrangler deployments list | grep "production" | head -n 1 | awk '{print $6}') # Crude parsing
  if [[ "$LATEST_DEPLOYMENT_URL" == https://* ]]; then
      ENDPOINT=$LATEST_DEPLOYMENT_URL
      echo "✨ Endpoint encontrado a través de 'wrangler deployments list': $ENDPOINT"
  else
      echo "   No se pudo encontrar un endpoint alternativo. Por favor, actualiza el archivo de configuración manualmente."
  fi
fi

# Return to the original directory (project root)
cd "$ORIGINAL_DIR"

if [ -n "$ENDPOINT" ]; then # Proceed only if endpoint was found
  echo "✅ Endpoint detectado: $ENDPOINT"

  # Ensure client config file exists, create a base structure if not
  if [ ! -f "$CLIENT_CONFIG_FILE" ]; then
    echo "⚠️ $CLIENT_CONFIG_FILE no existe. Creando archivo base..."
    # Basic JSON structure
    echo '{
      "client_id": "",
      "providers": {
        "cloudflare": {"endpoint": "", "type": "cdn", "quota": 1000, "count": 0},
        "fastly": {"endpoint": "", "type": "cdn", "quota": 500, "count": 0},
        "vercel": {"endpoint": "", "type": "serverless", "quota": 200, "count": 0},
        "netlify": {"endpoint": "", "type": "serverless", "quota": 200, "count": 0}
      }
    }' > "$CLIENT_CONFIG_FILE"
    echo "$CLIENT_CONFIG_FILE creado con estructura base."
  fi

  # Check if jq is installed for automatic config update
  if ! command -v jq &> /dev/null; then
    echo "❌ jq no está instalado. Por favor, instálalo para actualizar la configuración automáticamente."
    echo "   Puedes editar $CLIENT_CONFIG_FILE manualmente para añadir el endpoint: $ENDPOINT"
  else
    TMP_FILE=$(mktemp) # Create a temporary file for safe editing
    # Update Cloudflare provider's endpoint using jq
    jq --arg endpoint "$ENDPOINT" '.providers.cloudflare.endpoint = $endpoint' "$CLIENT_CONFIG_FILE" > "$TMP_FILE" && mv "$TMP_FILE" "$CLIENT_CONFIG_FILE"
    echo "✅ $CLIENT_CONFIG_FILE actualizado con el endpoint de Cloudflare."
  fi
fi

echo "🛠️ Generando configuración final del cliente en $CLIENT_GENERATED_CONFIG_FILE..."
# Check for uuidgen to create a unique client_id
if ! command -v uuidgen &> /dev/null; then
  echo "⚠️ uuidgen no está instalado. Se usará un client_id genérico."
  echo "   Para un client_id único, por favor instala uuidgen."
  CLIENT_ID="generic-phantom-client-$(date +%s)" # Fallback client_id
else
  CLIENT_ID=$(uuidgen)
fi

# Use jq to construct the final generated config from the (potentially updated) client_config.json
# This assumes client_config.json has the necessary provider structures.
if [ -f "$CLIENT_CONFIG_FILE" ] && command -v jq &> /dev/null; then
  jq --arg client_id "$CLIENT_ID" '
    .client_id = $client_id
    # Ensure providers object exists
    | .providers = (if .providers then .providers else {} end)
    # Ensure specific providers exist or initialize them minimally
    | .providers.cloudflare = (if .providers.cloudflare then .providers.cloudflare else {"endpoint": "", "type": "cdn"} end)
    | .providers.fastly = (if .providers.fastly then .providers.fastly else {"endpoint": "", "type": "cdn"} end)
    | .providers.vercel = (if .providers.vercel then .providers.vercel else {"endpoint": "", "type": "serverless"} end)
    | .providers.netlify = (if .providers.netlify then .providers.netlify else {"endpoint": "", "type": "serverless"} end)
  ' "$CLIENT_CONFIG_FILE" > "$CLIENT_GENERATED_CONFIG_FILE"
  echo "✅ $CLIENT_GENERATED_CONFIG_FILE creado/actualizado."
elif [ -f "$CLIENT_CONFIG_FILE" ]; then # jq not found, but base config exists
  echo "⚠️ jq no encontrado. Copiando $CLIENT_CONFIG_FILE a $CLIENT_GENERATED_CONFIG_FILE y añadiendo client_id manualmente (si es posible)."
  cp "$CLIENT_CONFIG_FILE" "$CLIENT_GENERATED_CONFIG_FILE"
  # Simple sed fallback to add client_id if it's simple JSON and client_id is missing. This is fragile.
  if ! grep -q "\"client_id\"" "$CLIENT_GENERATED_CONFIG_FILE"; then
    sed -i "1s/{/{\n  \"client_id\": \"$CLIENT_ID\",/" "$CLIENT_GENERATED_CONFIG_FILE"
  fi
  echo "   Por favor, verifica $CLIENT_GENERATED_CONFIG_FILE."
else # Base config also doesn't exist
  echo "❌ No se pudo generar $CLIENT_GENERATED_CONFIG_FILE porque $CLIENT_CONFIG_FILE no existe y jq no está disponible."
  echo "   Por favor, crea $CLIENT_CONFIG_FILE manualmente."
fi


echo ""
echo "🎉 ¡Despliegue y configuración (parcialmente) completados!"
echo "   Verifica $DEPLOY_LOG_PATH para detalles del despliegue."
if [ -f "$CLIENT_GENERATED_CONFIG_FILE" ]; then
  echo "   La configuración del cliente generada está en: $CLIENT_GENERATED_CONFIG_FILE"
  echo "   Para ejecutar el cliente:"
  echo "   python ${CLIENT_CONFIG_DIR}/stealth_client.py -c $CLIENT_GENERATED_CONFIG_FILE"
else
  echo "   Hubo un problema generando la configuración del cliente. Revisa los mensajes anteriores."
fi
echo "   Asegúrate de que el worker esté funcionando correctamente y que el endpoint en la configuración del cliente sea el correcto."
echo ""
echo "NOTA: Este script asume que tienes 'vault', 'wrangler', 'jq', y 'uuidgen' instalados y configurados."

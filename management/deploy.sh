#!/bin/bash
# management/deploy.sh (Versión Mejorada)

# Configuración automática
CLOUDFLARE_API_URL="https://api.cloudflare.com/client/v4"
FASTLY_API_URL="https://api.fastly.com"
DEPLOY_LOG="phantom_deploy.log"

# Autenticación integrada
authenticate() {
  echo "🔐 Autenticando en servicios..."
  # Ensure vault is installed and configured before running.
  # Consider adding checks for vault and other CLIs.
  export CLOUDFLARE_API_TOKEN=$(vault read -field=token cloudflare/creds)
  export FASTLY_API_KEY=$(vault read -field=key fastly/creds)
  # Ensure VERCEL_TOKEN_FILE is set and points to a valid file.
  # vercel token import $VERCEL_TOKEN_FILE
  # netlify login --new # This requires interactive login, consider alternatives for automation.
  echo "Autenticación completada (parcialmente, Vercel y Netlify requieren configuración manual o tokens)"
}

# Despliegue con gestión de errores
deploy_cloudflare() {
  echo "🚀 Desplegando en Cloudflare..."
  # Ensure wrangler is installed and configured.
  # Ensure the script is run from the repo root or adjust paths.
  if [ -d "orchestrator/cloudflare" ]; then
    cd orchestrator/cloudflare
    # Check if wrangler is installed
    if ! command -v wrangler &> /dev/null
    then
        echo "wrangler CLI could not be found, please install it."
        exit 1
    fi
    wrangler deploy >> ../../$DEPLOY_LOG 2>&1 || { # Adjusted log path
      echo "❌ Error en despliegue Cloudflare";
      tail -n 20 ../../$DEPLOY_LOG; # Adjusted log path
      cd ../.. # Return to original directory
      exit 1;
    }
    cd ../.. # Return to original directory
  else
    echo "❌ Directorio orchestrator/cloudflare no encontrado."
    exit 1
  fi

  # Configuración automática
  # This assumes wrangler info output format. May need adjustment.
  # Also, ensure jq is installed.
  if ! command -v jq &> /dev/null
  then
      echo "jq could not be found, please install it."
      exit 1
  fi
  # The following line needs client/config.json to exist and be writable.
  # Also, CLOUDFLARE_ENDPOINT=$(wrangler info | grep 'https://' | head -1) might not work if wrangler is run from a different directory.
  # This needs to be run from orchestrator/cloudflare or wrangler needs the path to its config.
  # Assuming client/config.json exists at the root for now.
  # This part is problematic as `wrangler info` needs to be run in the context of the worker.
  # For now, this will be commented out as it requires a successful deployment first.
  # CLOUDFLARE_ENDPOINT=$(cd orchestrator/cloudflare && wrangler info | grep 'https://' | head -1)
  # if [ -f "client/config.json" ]; then
  #   jq --arg endpoint "$CLOUDFLARE_ENDPOINT" \
  #     '.providers.cloudflare.endpoint = $endpoint' \
  #     client/config.json > tmp && mv tmp client/config.json
  # else
  #   echo "client/config.json not found for endpoint update."
  # fi
  echo "Despliegue Cloudflare completado (endpoint no actualizado en config.json automáticamente)."
}

# Placeholder for other deployment functions
deploy_fastly() {
  echo "💨 Desplegando en Fastly (Placeholder)..."
  # Add Fastly deployment logic here
}

deploy_vercel() {
  echo "🔼 Desplegando en Vercel (Placeholder)..."
  # Add Vercel deployment logic here
}

deploy_netlify() {
  echo "🌐 Desplegando en Netlify (Placeholder)..."
  # Add Netlify deployment logic here
}


generate_client_config() {
  echo "🛠️ Generando configuración cliente..."
  # Ensure client/config.json exists or provide a template for it.
  # The current script assumes parts of client/config.json exist.
  # Create a dummy client/config.json if it doesn't exist for generation.
  if [ ! -f "client/config.json" ]; then
    echo "{\"providers\": {\"cloudflare\": {}, \"fastly\": {}, \"vercel\": {}, \"netlify\": {}}}" > client/config.json
    echo "Creado client/config.json temporal."
  fi

  CONFIG_TEMPLATE="{
    \"client_id\": \"$(uuidgen)\",
    \"providers\": {
      \"cloudflare\": $(jq '.providers.cloudflare' client/config.json),
      \"fastly\": $(jq '.providers.fastly' client/config.json),
      \"vercel\": $(jq '.providers.vercel' client/config.json),
      \"netlify\": $(jq '.providers.netlify' client/config.json)
    }
  }"

  echo $CONFIG_TEMPLATE > client/config_generated.json
  echo "✅ Configuración generada: client/config_generated.json"
}

# Función principal
main() {
  authenticate
  deploy_cloudflare
  deploy_fastly
  deploy_vercel
  deploy_netlify
  generate_client_config
  echo "🎉 Despliegue completado!"
  echo "➡️ Ejecuta: python client/stealth_client.py -c client/config_generated.json"
}

main

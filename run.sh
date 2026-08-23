#!/usr/bin/with-contenv bashio
bashio::log.info "Iniciando WebJWT..."

exec dotnet /app/WebJWT.dll --urls "http://0.0.0.0:8181"
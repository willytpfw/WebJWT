#!/bin/sh
set -e

#!/usr/bin/with-contenv bashio
export JwtKey=$(bashio::config 'JwtKey')
export JwtUsername=$(bashio::config 'JwtUsername')
export JwtPassword=$(bashio::config 'JwtPassword')
exec dotnet /app/WebJWT.dll --urls "http://0.0.0.0:8181"


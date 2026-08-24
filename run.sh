#!/bin/sh

set -e

JwtKey=$(jq -r '.JwtKey' /data/options.json)
JwtUsername=$(jq -r '.JwtUsername' /data/options.json)
JwtPassword=$(jq -r '.JwtPassword' /data/options.json)

export JwtKey="$JwtKey"
export JwtUsername="$JwtUsername"
export JwtPassword="$JwtPassword"

exec dotnet /app/WebJWT.dll --urls "http://0.0.0.0:8181"


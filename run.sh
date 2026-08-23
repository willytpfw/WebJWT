#!/bin/sh
set -e
exec dotnet /app/WebJWT.dll --urls "http://0.0.0.0:8181"
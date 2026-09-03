# WebJWT

Simple minimal JWT authentication example built with .NET 8 (minimal API).

## Overview

This project exposes a small HTTP API that issues and validates JWTs.

Endpoints
- `GET /` - public, returns "Hello World".
- `GET /protected` - requires a valid Bearer JWT.
- `GET /protectedScope` - requires a valid Bearer JWT and the claim `Scope` equal to `myapi:hacker`.
- `GET /auth/{user}/{password}` - issues a JWT when credentials match configured secrets.
- `GET /Dec?Token={token}` - validates a token and returns the `GUID` claim if valid.

JWT claims included when issuing a token:
- `ClaimTypes.Name` (username)
- `Scope` = `myapi:hacker`
- `GUID` = random GUID

## Technologies
- .NET 8 (net8.0)
- C# 12 minimal API
- `Microsoft.AspNetCore.Authentication.JwtBearer`
- `DotNetEnv` (loads `.env` into environment variables)

## Configuration & Secrets
The app reads secrets from one of two sources depending on the `Production` flag in `appsettings.json`:
- If `Production: true` -> secrets are read from `dotnet user-secrets` (requires `UserSecretsId` in the project file).
- If `Production: false` -> secrets are read from a `.env` file located in the project root and loaded via `DotNetEnv`.

Important configuration keys (configuration path):
- `Jwt:Key` - symmetric signing key (store a long random secret)
- `Jwt:Username` - username allowed to request tokens
- `Jwt:Password` - password for the username

When using `.env` use double underscores to map `:` in configuration keys. Example `.env`:

```
Jwt__Key=your_super_secret_key_here
Jwt__Username=willytpfw
Jwt__Password=Dejamelo1
```

Security notes:
- Do not commit `.env` or user-secrets to source control. Add `.env` to `.gitignore`.
- Use HTTPS in production and use strong random keys for `Jwt:Key` (recommend at least 32+ bytes).

## Build and Run (local)

1. Restore and build:

```bash
dotnet restore
dotnet build
```

2. Run:

```bash
dotnet run
```

The app reads `appsettings.json` by default. To use `.env` ensure `appsettings.json` has `"Production": false` (default in this repo).

To use `dotnet user-secrets` (production mode in this repo):

```bash
# enable production in appsettings.json or set environment variable
# set secrets (run from project folder)
dotnet user-secrets set "Jwt:Key" "<your-secret>"
dotnet user-secrets set "Jwt:Username" "willytpfw"
dotnet user-secrets set "Jwt:Password" "Dejamelo1"
```

## Home Assistant Integration
You can call this API from Home Assistant using the REST integrations. Example flow:

1. Obtain a token and store it in a sensor (poll or on demand). Example `configuration.yaml`:

```yaml
sensor:
  - platform: rest
    name: webjwt_token
    resource: "http://<HOST>:<PORT>/auth/willytpfw/Dejamelo1"
    method: GET
    value_template: "{{ value }}"
    scan_interval: 3600  # refresh hourly (or as needed)
```

2. Call protected endpoints using the token stored in the sensor. Example `rest_command`:

```yaml
rest_command:
  call_webjwt_protected:
    url: "http://<HOST>:<PORT>/protected"
    method: GET
    headers:
      Authorization: "Bearer {{ states('sensor.webjwt_token') }}"
```

3. Call the command from automations/scripts or use `rest_command` to fetch other protected endpoints. For the scoped endpoint, the issued token contains `Scope=myapi:hacker`, so the same token will work for `protectedScope`.

Note: adapt `<HOST>:<PORT>` to where this service runs (use internal network address reachable by Home Assistant). If Home Assistant and the API run on the same machine, you can use `http://localhost:5000` or container host IP.

## Docker (optional)
If you want to containerize the app, add a `Dockerfile` and build:

```bash
docker build -t webjwt .
docker run -e Production=false -p 5000:80 webjwt
```

## Project notes
- `appsettings.json` contains a `Production` boolean key that controls which secret source is used.
- The project includes `DotNetEnv` and `Microsoft.AspNetCore.Authentication.JwtBearer` packages.
- User secrets support is enabled via `UserSecretsId` in `WebJWT.csproj`.

## Troubleshooting
- If tokens fail validation: ensure the same `Jwt:Key` is used for issuing and validating tokens, and that you are sending the token as `Authorization: Bearer <token>`.
- If using `.env`, restart the app after editing `.env` so `DotNetEnv` reloads values.

## License & Contribution
This repository is a small sample. Modify as needed. Keep secrets out of version control.


---
Generated README for the `WebJWT` project.

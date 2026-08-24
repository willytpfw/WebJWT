// PSEUDOCODE / PLAN (detailed):
// 1. Read secret values from configuration:
//    - Jwt:Key (required) used as the symmetric signing key.
//    - Jwt:Username (optional, used to validate /auth credentials).
//    - Jwt:Password (optional).
// 2. Validate presence of Jwt:Key and throw a clear error if missing.
// 3. Configure authentication to use JWT Bearer with a SymmetricSecurityKey
//    created from Jwt:Key. Disable issuer/audience validation for parity with
//    existing behavior.
// 4. Keep the existing endpoints:
//    - "/" public
//    - "/protected" requires any authenticated user
//    - "/protectedScope" requires claim "Scope" == "myapi:hacker"
//    - "/auth/{user}/{password}" validates against configured credentials and
//      issues a JWT signed with the secret key. Include Name, Scope, GUID claims.
//    - "/Dec" validates an incoming token (from query string "Token") and returns GUID claim if valid.
// 5. Replace hard-coded key/credentials with configuration lookups so values can be
//    provided via user-secrets, environment variables, or other configuration providers.
// 6. Use tokenHandler.WriteToken(token) to produce the compact JWT string.
// 7. Handle missing credentials gracefully (return 401) and token validation exceptions with 403.

// Note: Configure secrets with `dotnet user-secrets set "Jwt:Key" "<your-secret>"`
// and similarly for "Jwt:Username" and "Jwt:Password" or set environment variables.

using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using DotNetEnv;
using System.Reflection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.UserSecrets;

var builder = WebApplication.CreateBuilder(args);

// Determine source for secrets based on appsettings:Production
var isProduction = builder.Configuration.GetValue<bool>("Production");

if (isProduction)
{
    // Load secrets from dotnet user-secrets (UserSecretsId must be set in csproj)
    builder.Configuration.AddUserSecrets(Assembly.GetEntryAssembly()!, optional: true);
}
else
{
    // Load .env into environment variables and ensure env vars provider is added
    Env.Load();
    builder.Configuration.AddEnvironmentVariables();
}

// Read secrets/configuration
var jwtKey = builder.Configuration["JwtKey"];
var jwtUsername = builder.Configuration["JwtUsername"];
var jwtPassword = builder.Configuration["JwtPassword"];

if (string.IsNullOrWhiteSpace(jwtKey))
{
    throw new InvalidOperationException($@"Configuration value 'Jwt:Key' is required. Set it via user-secrets or environment variables. {DateTime.UtcNow}");
}

var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));

builder.Services.AddAuthorization();
builder.Services
    .AddAuthentication("Bearer")
    .AddJwtBearer(opt =>
    {
        opt.RequireHttpsMetadata = false;
        opt.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = false,
            ValidateIssuer = false,
            IssuerSigningKey = signingKey
        };
    });

var app = builder.Build();

app.MapGet("/", () => "Hello World");

app.MapGet("/protectedScope", (ClaimsPrincipal user) => "Hello World protejido eres Hack:" + user.Identity?.Name)
   .RequireAuthorization(prop => prop.RequireClaim("Scope", "myapi:hacker"));

app.MapGet("/protected", (ClaimsPrincipal user) => "Hello World protejido eres:" + user.Identity?.Name)
   .RequireAuthorization();

app.MapGet("/auth/{user}/{password}", (string user, string password) =>
{
    // If configured credentials are present, validate against them.
    // If they are not configured, reject for safety.
    if (string.IsNullOrEmpty(jwtUsername) || string.IsNullOrEmpty(jwtPassword))
    {
        return Results.StatusCode(StatusCodes.Status401Unauthorized);
    }

    if (user == jwtUsername && password == jwtPassword)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.Name, user),
                new Claim("Scope", "myapi:hacker"),
                new Claim("GUID", Guid.NewGuid().ToString())
            }),
            Expires = DateTime.UtcNow.AddMonths(1),
            SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        var tokenString = tokenHandler.WriteToken(token);
        return Results.Text(tokenString);
    }

    return Results.StatusCode(StatusCodes.Status401Unauthorized);
});

app.MapGet("/Dec", (HttpContext context) =>
{
    string token = context.Request.Query["Token"].ToString();
    if (string.IsNullOrWhiteSpace(token))
    {
        return Results.StatusCode(StatusCodes.Status400BadRequest);
    }

    try
    {
        var handler = new JwtSecurityTokenHandler();
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            IssuerSigningKey = signingKey
        };

        SecurityToken validatedToken;
        var principal = handler.ValidateToken(token, validationParameters, out validatedToken);
        if (validatedToken is JwtSecurityToken jwt)
        {
            var sGUID = jwt.Claims.FirstOrDefault(c => c.Type == "GUID")?.Value;
            if (sGUID is not null)
            {
                return Results.Ok(new { GUID = sGUID });
            }

            return Results.StatusCode(StatusCodes.Status404NotFound);
        }

        return Results.StatusCode(StatusCodes.Status403Forbidden);
    }
    catch (Exception)
    {
        return Results.StatusCode(StatusCodes.Status403Forbidden);
    }
});

app.Run();
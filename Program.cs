using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Security.Claims;


var builder = WebApplication.CreateBuilder(args);

string key = "1234567890123567890123456789011234567890";

builder.Services.AddAuthorization();
builder.Services.AddAuthentication("Bearer").AddJwtBearer(opt =>
{
    var signinKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
    var signCredentials = new SigningCredentials(signinKey, SecurityAlgorithms.HmacSha256Signature);

    opt.RequireHttpsMetadata = false;
    opt.TokenValidationParameters = new TokenValidationParameters()
    {
        ValidateAudience = false,
        ValidateIssuer = false,
        IssuerSigningKey = signinKey,
    };
});

var app = builder.Build();

app.MapGet("/", () => "Hello World");
app.MapGet("/protectedScope", (ClaimsPrincipal user) => "Hello World protejido eres Hack:" + user.Identity?.Name).RequireAuthorization(prop => prop.RequireClaim("Scope", "myapi:hacker"));

app.MapGet("/protected", (ClaimsPrincipal user) => "Hello World protejido eres:" + user.Identity?.Name).RequireAuthorization();


app.MapGet("/auth/{user}/{password}", (string user, string password) =>
{
    if (user.Equals("willytpfw") && password.Equals("Dejamelo1"))
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var byteKey = Encoding.UTF8.GetBytes(key);
        var tokenDes = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Name, user),
                new Claim("Scope","myapi:Hacker"),
                new Claim("GUID",Guid.NewGuid().ToString())
            }),
            Expires = DateTime.UtcNow.AddMonths(1),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(byteKey), SecurityAlgorithms.HmacSha256Signature)
        };
        var token = tokenHandler.CreateToken(tokenDes);

        return token.UnsafeToString();
    }
    else
    { return "Usuario no valido"; }
});


app.MapGet("/Dec", (HttpContext context) =>
{
    string token = context.Request.Query["Token"].ToString();
    try
    {
        var handler = new JwtSecurityTokenHandler();
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key))
        };

        SecurityToken validatedToken;
        var principal = handler.ValidateToken(token, validationParameters, out validatedToken);
        if (validatedToken != null)
        {
            // Obtain specific key of claim
            var specificClaims = (validatedToken as JwtSecurityToken).Claims.Where(c => c.Type == "GUID");
            var sGUID = specificClaims.ToList().FirstOrDefault().Value;
            return Results.Ok(new { GUID = sGUID });
        }
        else { return Results.StatusCode(StatusCodes.Status403Forbidden); }
    }
    catch (Exception)
    {
        return Results.StatusCode(StatusCodes.Status403Forbidden);
    }
});


app.Run();

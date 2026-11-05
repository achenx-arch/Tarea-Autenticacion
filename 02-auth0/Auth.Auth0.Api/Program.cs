using System.Collections.Concurrent;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// ---------------------------------------------------------------
// Configuración de Auth0
// Domain   -> dotnet user-secrets set "Auth0:Domain" "tu-tenant.us.auth0.com"
// Audience -> appsettings.json (identifier de la API creada en Auth0)
// ---------------------------------------------------------------
var auth0Domain = builder.Configuration["Auth0:Domain"]?
    .Replace("https://", "").TrimEnd('/');
var auth0Audience = builder.Configuration["Auth0:Audience"];

if (string.IsNullOrWhiteSpace(auth0Domain) || string.IsNullOrWhiteSpace(auth0Audience))
{
    // Fallar temprano con un mensaje claro es mejor que un 401 misterioso.
    throw new InvalidOperationException(
        "Falta configurar Auth0. Ejecuta: dotnet user-secrets set \"Auth0:Domain\" \"tu-tenant.us.auth0.com\"");
}

// ---------------------------------------------------------------
// Servicios
// ---------------------------------------------------------------
builder.Services.AddOpenApi();

// CORS: solo nuestro frontend (React en el puerto 5173) puede llamar a la API desde el navegador.
builder.Services.AddCors(options =>
{
    options.AddPolicy("web", policy => policy
        .WithOrigins("http://localhost:5173")
        .AllowAnyHeader()   // necesitamos "Authorization"
        .AllowAnyMethod());
});

// Autenticación con JWT Bearer emitidos por Auth0.
//
// ¿Por qué aquí NO hay llave secreta (a diferencia de la Parte A)?
// Auth0 firma los access tokens con RS256 (criptografía ASIMÉTRICA):
//   - Auth0 guarda la llave PRIVADA y es el único que puede firmar.
//   - Publica las llaves PÚBLICAS en https://{domain}/.well-known/jwks.json (JWKS).
// Con Authority, la API descarga https://{domain}/.well-known/openid-configuration,
// de ahí obtiene la URL del JWKS y cachea las llaves públicas para verificar firmas.
// Una llave pública solo sirve para VERIFICAR, no para firmar: no es un secreto.
// Si Auth0 rota sus llaves, la API las vuelve a descargar automáticamente.
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        // Issuer esperado (claim "iss") y origen del JWKS.
        options.Authority = $"https://{auth0Domain}/";

        // Audience esperada (claim "aud"): el token debe haber sido pedido PARA esta API.
        options.Audience = auth0Audience;

        // Conservamos los nombres originales de los claims ("sub", "permissions").
        options.MapInboundClaims = false;

        options.TokenValidationParameters = new TokenValidationParameters
        {
            NameClaimType = "sub",
        };
    });

// Políticas basadas en PERMISOS (RBAC de Auth0).
// Con "Enable RBAC" + "Add Permissions in the Access Token" activos en la API de Auth0,
// el access token trae:  "permissions": ["read:messages"].
// Un usuario autenticado SIN ese permiso recibe 403 (autenticado, pero no autorizado).
// Rol Lector        -> "permissions": ["read:messages"]
// Rol Administrador -> "permissions": ["delete:messages", "read:messages"]
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("read:messages", policy => policy
        .RequireAuthenticatedUser()
        .RequireClaim("permissions", "read:messages"))
    // TAREA: nueva política. Exige el valor delete:messages en el claim permissions.
    .AddPolicy("delete:messages", policy => policy
        .RequireAuthenticatedUser()
        .RequireClaim("permissions", "delete:messages"));

var app = builder.Build();

// ---------------------------------------------------------------
// Pipeline HTTP
// ---------------------------------------------------------------
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseCors("web");
app.UseAuthentication();
app.UseAuthorization();

// ---------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------
app.MapGet("/api/health", () => Results.Ok(new { status = "ok", time = DateTime.UtcNow }));

// Anónimo: cualquiera puede llamarlo -> 200
app.MapGet("/api/public", () => Results.Ok(new
{
    message = "Endpoint público: no necesitas token para ver esto.",
}));

// Requiere un access token válido de Auth0 -> 200 / 401
app.MapGet("/api/private", (ClaimsPrincipal user) => Results.Ok(new
{
    message = "Endpoint privado: tu token de Auth0 es válido.",
    sub = user.FindFirstValue("sub"),
    permissions = GetPermissions(user),
}))
.RequireAuthorization();

// Requiere token válido Y el permiso read:messages -> 200 / 401 / 403
app.MapGet("/api/private-scoped", (ClaimsPrincipal user) => Results.Ok(new
{
    message = "Endpoint con permiso: tienes 'read:messages'.",
    sub = user.FindFirstValue("sub"),
    permissions = GetPermissions(user),
}))
.RequireAuthorization("read:messages");

// ---------------------------------------------------------------
// TAREA · Parte 2: recurso Message en memoria + RBAC
// ---------------------------------------------------------------
// ConcurrentDictionary porque Kestrel atiende peticiones en paralelo.
var messages = new ConcurrentDictionary<int, Message>(new[]
{
    new Message(1, "Recordatorio: el parcial de Desarrollo Web es el viernes.", "catedratico"),
    new Message(2, "Ya están publicadas las notas de la tarea 4.", "catedratico"),
    new Message(3, "Mensaje de prueba para eliminar como Administrador.", "sistema"),
    new Message(4, "Otro mensaje de prueba.", "sistema"),
}.ToDictionary(m => m.Id));

var messagesApi = app.MapGroup("/api/messages");

// GET /api/messages -> requiere read:messages (Lector y Administrador)
messagesApi.MapGet("", () => Results.Ok(messages.Values.OrderBy(m => m.Id)))
    .RequireAuthorization("read:messages");

// DELETE /api/messages/{id} -> requiere delete:messages (solo Administrador)
// Un Lector autenticado recibe 403: la API sabe quién es, pero no tiene el permiso.
messagesApi.MapDelete("/{id:int}", (int id, ClaimsPrincipal user, ILogger<Message> logger) =>
{
    var sub = user.FindFirstValue("sub");

    if (!messages.TryRemove(id, out var removed))
        return Results.NotFound(new { message = $"No existe el mensaje {id}." });

    // Auditoría: quién borró qué.
    logger.LogInformation("Mensaje {MessageId} (\"{Text}\") eliminado por sub={Sub}", removed.Id, removed.Text, sub);
    return Results.NoContent(); // 204
})
.RequireAuthorization("delete:messages");

app.Run();

// El arreglo "permissions" del JWT llega como varios claims con el mismo nombre.
static string[] GetPermissions(ClaimsPrincipal user) =>
    user.FindAll("permissions").Select(c => c.Value).ToArray();

record Message(int Id, string Text, string CreatedBy);

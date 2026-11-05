using System.Net.Mail;
using Auth.Local.Api.Auth;
using Auth.Local.Api.Contracts;
using Auth.Local.Api.Data;
using Auth.Local.Api.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Auth.Local.Api.Endpoints;

public static class AuthEndpoints
{
    private const int MinPasswordLength = 8;

    public static IEndpointRouteBuilder MapAuthEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/auth");

        group.MapPost("/register", Register);

        // Máximo 5 intentos por minuto por IP (política definida en Program.cs). El 6.º -> 429.
        group.MapPost("/login", Login)
            .RequireRateLimiting(RateLimitPolicies.Login);

        // Renovación de sesión con rotación del refresh token.
        group.MapPost("/refresh", Refresh);

        // Cierre de sesión: revoca el refresh token en el servidor.
        group.MapPost("/logout", Logout);

        return app;
    }

    // POST /api/auth/register
    private static async Task<IResult> Register(
        RegisterRequest request,
        AppDbContext db,
        IPasswordHasher<User> hasher)
    {
        var email = NormalizeEmail(request.Email);

        // 1) Validación de entrada: nunca confiamos en lo que manda el cliente.
        var errors = new Dictionary<string, string[]>();
        if (email is null || !MailAddress.TryCreate(email, out _))
            errors["email"] = ["El correo no es válido."];
        if (string.IsNullOrEmpty(request.Password) || request.Password.Length < MinPasswordLength)
            errors["password"] = [$"La contraseña debe tener al menos {MinPasswordLength} caracteres."];
        if (errors.Count > 0)
            return Results.ValidationProblem(errors); // 400

        // 2) El correo debe ser único.
        if (await db.Users.AnyAsync(u => u.Email == email))
            return Results.Conflict(new { message = "El correo ya está registrado." }); // 409

        // 3) Guardamos SOLO el hash (PBKDF2 + sal aleatoria).
        var user = new User { Email = email!, PasswordHash = "" };
        user.PasswordHash = hasher.HashPassword(user, request.Password);

        db.Users.Add(user);
        await db.SaveChangesAsync();

        return Results.Created($"/api/users/{user.Id}", new { user.Id, user.Email }); // 201
    }

    // POST /api/auth/login
    private static async Task<IResult> Login(
        LoginRequest request,
        AppDbContext db,
        IPasswordHasher<User> hasher,
        TokenService tokens,
        RefreshTokenService refreshTokens)
    {
        var email = NormalizeEmail(request.Email);
        var user = email is null ? null : await db.Users.SingleOrDefaultAsync(u => u.Email == email);

        if (user is null)
        {
            // Igualamos el tiempo de respuesta para no revelar qué correos existen.
            hasher.VerifyHashedPassword(DummyUser, DummyUser.PasswordHash, request.Password ?? "");
            return InvalidCredentials();
        }

        var result = hasher.VerifyHashedPassword(user, user.PasswordHash, request.Password ?? "");
        if (result == PasswordVerificationResult.Failed)
            return InvalidCredentials();

        if (result == PasswordVerificationResult.SuccessRehashNeeded)
        {
            user.PasswordHash = hasher.HashPassword(user, request.Password!);
            await db.SaveChangesAsync();
        }

        // Con 2FA activo todavía NO entregamos refresh token: primero hay que pasar /2fa/verify.
        if (user.TwoFactorEnabled)
            return Results.Ok(new { requires2fa = true, tempToken = tokens.CreateTwoFactorToken(user) });

        return Results.Ok(await IssueSessionAsync(user, tokens, refreshTokens));
    }

    // POST /api/auth/refresh  -> { accessToken, refreshToken } nuevos
    private static async Task<IResult> Refresh(
        RefreshTokenRequest request,
        TokenService tokens,
        RefreshTokenService refreshTokens)
    {
        var result = await refreshTokens.RotateAsync(request.RefreshToken);

        return result.Outcome switch
        {
            RefreshOutcome.Success => Results.Ok(new TokenPairResponse(
                tokens.CreateAccessToken(result.User!),
                result.NewRefreshToken!)),

            RefreshOutcome.Reused => Results.Json(
                new { message = "Refresh token reutilizado. Por seguridad se cerraron todas tus sesiones." },
                statusCode: StatusCodes.Status401Unauthorized),

            _ => Results.Json(
                new { message = "Refresh token inválido o vencido." },
                statusCode: StatusCodes.Status401Unauthorized),
        };
    }

    // POST /api/auth/logout  -> 204 siempre (no revelamos si el token existía)
    private static async Task<IResult> Logout(RefreshTokenRequest request, RefreshTokenService refreshTokens)
    {
        await refreshTokens.RevokeAsync(request.RefreshToken);
        return Results.NoContent();
    }

    /// <summary>Emite el par access + refresh. Lo usan el login y la verificación 2FA.</summary>
    internal static async Task<TokenPairResponse> IssueSessionAsync(
        User user, TokenService tokens, RefreshTokenService refreshTokens) =>
        new(tokens.CreateAccessToken(user), await refreshTokens.IssueAsync(user.Id));

    // Mensaje GENÉRICO: no decimos si falló el correo o la contraseña.
    private static IResult InvalidCredentials() =>
        Results.Json(new { message = "Correo o contraseña incorrectos." }, statusCode: StatusCodes.Status401Unauthorized);

    private static readonly User DummyUser = CreateDummyUser();

    private static User CreateDummyUser()
    {
        var user = new User { Email = "dummy@localhost", PasswordHash = "" };
        user.PasswordHash = new PasswordHasher<User>().HashPassword(user, Guid.NewGuid().ToString());
        return user;
    }

    private static string? NormalizeEmail(string? email) =>
        string.IsNullOrWhiteSpace(email) ? null : email.Trim().ToLowerInvariant();
}

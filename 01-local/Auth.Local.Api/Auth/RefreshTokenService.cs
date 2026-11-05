using System.Security.Cryptography;
using System.Text;
using Auth.Local.Api.Data;
using Auth.Local.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace Auth.Local.Api.Auth;

/// <summary>Resultado de intentar rotar un refresh token.</summary>
public enum RefreshOutcome
{
    Success,
    Invalid,  // no existe o ya venció
    Reused,   // ya estaba revocado: posible robo -> se revocó toda la familia del usuario
}

public record RefreshResult(RefreshOutcome Outcome, User? User = null, string? NewRefreshToken = null);

/// <summary>
/// Emite, rota y revoca refresh tokens.
/// - Valor aleatorio de 32 bytes con RandomNumberGenerator (CSPRNG).
/// - En la BD se guarda solo SHA-256(token).
/// - Cada uso lo revoca y entrega uno nuevo (rotación).
/// - Si llega uno ya revocado, asumimos que fue robado y revocamos TODOS los del usuario.
/// </summary>
public class RefreshTokenService(AppDbContext db, ILogger<RefreshTokenService> logger)
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromDays(7);
    private const int TokenSizeBytes = 32;

    /// <summary>Crea un refresh token nuevo para el usuario y devuelve el valor EN CLARO (solo esta vez).</summary>
    public async Task<string> IssueAsync(int userId)
    {
        var (raw, entity) = NewToken(userId);
        db.RefreshTokens.Add(entity);
        await db.SaveChangesAsync();
        return raw;
    }

    public async Task<RefreshResult> RotateAsync(string? rawToken)
    {
        if (string.IsNullOrWhiteSpace(rawToken))
            return new(RefreshOutcome.Invalid);

        var hash = Hash(rawToken);
        var current = await db.RefreshTokens
            .Include(t => t.User)
            .SingleOrDefaultAsync(t => t.TokenHash == hash);

        if (current is null)
            return new(RefreshOutcome.Invalid);

        // Detección de reutilización: un token revocado NUNCA debería volver a llegar.
        // Si llega, alguien más lo tiene (el atacante o el usuario legítimo): cortamos todo.
        if (current.RevokedAt is not null)
        {
            var revoked = await RevokeAllForUserAsync(current.UserId);
            logger.LogWarning(
                "Reutilización de refresh token detectada para el usuario {UserId}. Se revocaron {Count} tokens activos.",
                current.UserId, revoked);
            return new(RefreshOutcome.Reused);
        }

        if (current.ExpiresAt <= DateTime.UtcNow)
            return new(RefreshOutcome.Invalid);

        // Rotación dentro de una transacción: o se revoca el viejo Y se crea el nuevo, o nada.
        await using var tx = await db.Database.BeginTransactionAsync();

        var (raw, replacement) = NewToken(current.UserId);
        db.RefreshTokens.Add(replacement);
        await db.SaveChangesAsync(); // necesitamos el Id del nuevo

        current.RevokedAt = DateTime.UtcNow;
        current.ReplacedByTokenId = replacement.Id;
        await db.SaveChangesAsync();

        await tx.CommitAsync();
        return new(RefreshOutcome.Success, current.User, raw);
    }

    /// <summary>Revoca un token concreto (logout). Devuelve false si no existía o ya estaba revocado.</summary>
    public async Task<bool> RevokeAsync(string? rawToken)
    {
        if (string.IsNullOrWhiteSpace(rawToken))
            return false;

        var hash = Hash(rawToken);
        var token = await db.RefreshTokens.SingleOrDefaultAsync(t => t.TokenHash == hash);
        if (token is null || token.RevokedAt is not null)
            return false;

        token.RevokedAt = DateTime.UtcNow;
        await db.SaveChangesAsync();
        return true;
    }

    private Task<int> RevokeAllForUserAsync(int userId)
    {
        var now = DateTime.UtcNow;
        return db.RefreshTokens
            .Where(t => t.UserId == userId && t.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.RevokedAt, now));
    }

    private static (string Raw, RefreshToken Entity) NewToken(int userId)
    {
        var raw = Base64UrlEncode(RandomNumberGenerator.GetBytes(TokenSizeBytes));
        var now = DateTime.UtcNow;
        return (raw, new RefreshToken
        {
            UserId = userId,
            TokenHash = Hash(raw),
            CreatedAt = now,
            ExpiresAt = now.Add(Lifetime),
        });
    }

    public static string Hash(string rawToken) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(rawToken)));

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

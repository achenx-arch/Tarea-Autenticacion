using System.ComponentModel.DataAnnotations.Schema;

namespace Auth.Local.Api.Models;

/// <summary>
/// Refresh token persistido. Solo guardamos el HASH SHA-256 del valor que recibe el cliente:
/// si alguien roba la base de datos, no obtiene tokens utilizables.
/// </summary>
public class RefreshToken
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public User User { get; set; } = null!;

    /// <summary>SHA-256 en hexadecimal (64 caracteres) del token original.</summary>
    public required string TokenHash { get; set; }

    public DateTime ExpiresAt { get; set; }
    public DateTime CreatedAt { get; set; }

    /// <summary>Momento en que se revocó (por rotación, logout o reutilización). Null = vigente.</summary>
    public DateTime? RevokedAt { get; set; }

    /// <summary>Id del token que lo reemplazó al rotar. Permite seguir la "cadena" de rotaciones.</summary>
    public int? ReplacedByTokenId { get; set; }

    [NotMapped]
    public bool IsActive => RevokedAt is null && ExpiresAt > DateTime.UtcNow;
}

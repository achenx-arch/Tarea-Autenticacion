using Auth.Local.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace Auth.Local.Api.Data;

public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<User> Users => Set<User>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // El correo es único: no puede haber dos cuentas con el mismo email.
        modelBuilder.Entity<User>()
            .HasIndex(u => u.Email)
            .IsUnique();

        modelBuilder.Entity<RefreshToken>(entity =>
        {
            // Buscamos siempre por hash, así que lo indexamos (y es único).
            entity.HasIndex(t => t.TokenHash).IsUnique();
            entity.Property(t => t.TokenHash).HasMaxLength(64);

            entity.HasOne(t => t.User)
                .WithMany()
                .HasForeignKey(t => t.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });
    }
}

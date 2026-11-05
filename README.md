# Tarea · Autenticación: refresh tokens, rate limiting y RBAC con Auth0

**Estudiante:** Abner Amilcar Chen Xicol · **Carné:** 0902-23-10306
**Curso:** Desarrollo Web · Ingeniería en Sistemas · Universidad Mariano Gálvez de Guatemala, Cobán

Partí de la demo de clase (`01-local` y `02-auth0`) y le agregué lo que pide la tarea.

```
01-local/   Auth.Local.Api (ASP.NET Core 10 + SQLite)  ·  auth-local-web (React + Vite)
02-auth0/   Auth.Auth0.Api (ASP.NET Core 10)           ·  auth0-web (React + Auth0 SDK)
```

Las dos partes usan el puerto 5173 para el frontend, así que se ejecutan **una a la vez**.

**Requisitos:** .NET 10 SDK, Node.js LTS y un cliente HTTP (los archivos `requests.http` funcionan con la extensión REST Client de VS Code).

---

## Parte 1 · `01-local`

### Qué se agregó

| Requisito | Dónde |
|---|---|
| Entidad `RefreshToken` (Id, UserId, TokenHash, ExpiresAt, CreatedAt, RevokedAt, ReplacedByTokenId) | `Models/RefreshToken.cs`, `Data/AppDbContext.cs` |
| Token aleatorio de 32 bytes (`RandomNumberGenerator`); en la BD solo va SHA-256 | `Auth/RefreshTokenService.cs` |
| Login y `/2fa/verify` devuelven `accessToken` + `refreshToken` (7 días) | `Endpoints/AuthEndpoints.cs`, `Endpoints/TwoFactorEndpoints.cs` |
| `POST /api/auth/refresh` con rotación | `AuthEndpoints.Refresh` → `RefreshTokenService.RotateAsync` |
| Detección de reutilización: revoca todos los tokens activos del usuario y responde 401 | `RotateAsync` |
| `POST /api/auth/logout` revoca el refresh token | `AuthEndpoints.Logout` |
| Rate limiting: 5 intentos/min por IP en login y en `/2fa/verify` → 429 | `Program.cs` (`AddRateLimiter`) |
| React: ante un 401, llama a `/refresh` y reintenta la petición **una sola vez** | `src/auth/AuthContext.tsx` (`authFetch`) |
| El botón *Cerrar sesión* llama a `/api/auth/logout` | `src/components/Layout.tsx` |

### Ejecutar

```powershell
# API
cd 01-local/Auth.Local.Api
dotnet user-secrets set "Jwt:Key" "$([Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(48)))"
dotnet run                                   # http://localhost:5080
# Para probar la renovación automática con tokens de 1 minuto:
# dotnet run -- --Jwt:AccessTokenMinutes=1

# Frontend (otra terminal)
cd 01-local/auth-local-web
Copy-Item .env.example .env
npm install
npm run dev                                  # http://localhost:5173
```

Las pruebas están en `01-local/Auth.Local.Api/requests.http`, en las secciones **R.1–R.7** (refresh) y **RL** (rate limiting).
La base de datos `auth.db` se crea al iniciar la API. Para empezar limpio, bórrala.

---

## Parte 2 · `02-auth0`

### Configuración en Auth0

1. **Applications → APIs → (tu API)**
   - *Permissions*: `read:messages` y `delete:messages`.
   - *Settings*: **Enable RBAC** y **Add Permissions in the Access Token** activados.
2. **User Management → Roles**
   - `Lector` → `read:messages`
   - `Administrador` → `read:messages` y `delete:messages`
3. **Users**: crear dos usuarios de prueba y asignar un rol a cada uno.
4. **Applications → (tu SPA)**: Callback, Logout y Web Origins = `http://localhost:5173`.

### Qué se agregó

| Requisito | Dónde |
|---|---|
| Política `delete:messages` (claim `permissions`) | `Auth.Auth0.Api/Program.cs` |
| `Message` en memoria; `GET /api/messages` (read) y `DELETE /api/messages/{id}` (delete) | `Program.cs` |
| Log con el `sub` de quien elimina | `Program.cs` (`ILogger`) |
| Lista con botón *Eliminar*, oculto si el token no trae `delete:messages` | `auth0-web/src/components/MessagesPanel.tsx` |

### Ejecutar

```powershell
# API
cd 02-auth0/Auth.Auth0.Api
dotnet user-secrets set "Auth0:Domain" "TU-TENANT.us.auth0.com"
dotnet user-secrets set "Auth0:Audience" "IDENTIFIER-DE-TU-API"
dotnet run                                   # http://localhost:5090

# Frontend (otra terminal)
cd 02-auth0/auth0-web
Copy-Item .env.example .env                  # completa domain, client id y audience
npm install
npm run dev                                  # http://localhost:5173
```

Las pruebas 403 y 204 están al final de `02-auth0/Auth.Auth0.Api/requests.http`.

---

## Secretos

- La llave JWT y el dominio de Auth0 se guardan con **User Secrets**, fuera del repositorio.
- Los frontends solo versionan `.env.example`. El `.env` real está en `.gitignore`.
- `*.db` también está ignorado.
- Antes de cada commit hay que revisar que los `requests.http` no contengan tokens reales.
# Tarea-Autenticacion

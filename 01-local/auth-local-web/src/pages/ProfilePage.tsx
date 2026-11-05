import { useCallback, useEffect, useState } from 'react'
import { ApiError } from '../api/apiFetch'
import { useAuth } from '../auth/AuthContext'
import TokenPanel from '../components/TokenPanel'

interface Profile {
  id: string
  email: string
}

export default function ProfilePage() {
  const { token, authFetch } = useAuth()
  const [profile, setProfile] = useState<Profile | null>(null)
  const [error, setError] = useState<string | null>(null)

  // Llama al endpoint protegido. Si el access token expiró (401), authFetch renueva la
  // sesión con /api/auth/refresh y reintenta una vez. Si eso falla, ProtectedRoute nos manda a /login.
  const loadProfile = useCallback(async () => {
    setError(null)
    try {
      setProfile(await authFetch<Profile>('/api/profile'))
    } catch (err) {
      setError(err instanceof ApiError ? `${err.status}: ${err.message}` : 'Error de red')
    }
  }, [authFetch])

  useEffect(() => {
    loadProfile()
  }, [loadProfile])

  return (
    <>
      <section className="card">
        <h1>Mi perfil</h1>
        <p className="muted">
          Respuesta de <code>GET /api/profile</code> (datos tomados de los claims del token):
        </p>
        {profile && <pre>{JSON.stringify(profile, null, 2)}</pre>}
        {error && <p className="alert error">{error}</p>}
        <div className="actions">
          <button onClick={loadProfile}>Volver a llamar /api/profile</button>
        </div>
      </section>

      {token && <TokenPanel token={token} />}
    </>
  )
}

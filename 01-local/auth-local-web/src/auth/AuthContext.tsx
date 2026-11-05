/*
 * AuthContext: maneja la sesión del usuario en el frontend.
 *
 * ¿Dónde guardamos los tokens?
 *  - Memoria (useState/useRef): un XSS no puede leerlos de localStorage y no viajan solos
 *    como una cookie (sin CSRF). Desventaja: al recargar la página se pierde la sesión.
 *  - localStorage: persiste, pero cualquier script inyectado (XSS) puede robarlos.
 *  - Cookie HttpOnly + SameSite: lo ideal en producción para el refresh token.
 * En esta tarea ambos tokens viven en memoria.
 *
 * Renovación automática:
 *  authFetch() hace la petición; si la API responde 401 (access token vencido),
 *  llama UNA vez a /api/auth/refresh, guarda el par nuevo y reintenta la petición
 *  original UNA sola vez. Si el refresh falla, se cierra la sesión.
 */
import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from 'react'
import { apiFetch, ApiError } from '../api/apiFetch'

export interface TokenPair {
  accessToken: string
  refreshToken: string
}

interface AuthContextValue {
  token: string | null
  isAuthenticated: boolean
  /** Guarda el par recibido del login o de /2fa/verify. */
  login: (tokens: TokenPair) => void
  /** Revoca el refresh token en la API y limpia la sesión local. */
  logout: () => Promise<void>
  /** fetch autenticado con renovación automática ante 401. */
  authFetch: <T>(path: string, init?: RequestInit) => Promise<T>
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  // El access token va en estado para que la UI se re-renderice (TokenPanel, rutas protegidas).
  const [token, setToken] = useState<string | null>(null)
  // El refresh token no se muestra: basta con una ref.
  const refreshTokenRef = useRef<string | null>(null)
  const accessTokenRef = useRef<string | null>(null)
  // Si varias peticiones reciben 401 a la vez, todas esperan la MISMA renovación
  // (si cada una llamara a /refresh, la segunda usaría un token ya rotado -> reutilización -> 401).
  const pendingRefresh = useRef<Promise<string> | null>(null)

  const saveTokens = useCallback((tokens: TokenPair) => {
    accessTokenRef.current = tokens.accessToken
    refreshTokenRef.current = tokens.refreshToken
    setToken(tokens.accessToken)
  }, [])

  const clearSession = useCallback(() => {
    accessTokenRef.current = null
    refreshTokenRef.current = null
    setToken(null)
  }, [])

  const logout = useCallback(async () => {
    const refreshToken = refreshTokenRef.current
    clearSession()
    if (!refreshToken) return
    try {
      await apiFetch<void>('/api/auth/logout', {
        method: 'POST',
        body: JSON.stringify({ refreshToken }),
      })
    } catch (err) {
      console.warn('No se pudo revocar el refresh token en el servidor', err)
    }
  }, [clearSession])

  /** Pide un par nuevo a /api/auth/refresh y devuelve el access token nuevo. */
  const renewSession = useCallback((): Promise<string> => {
    if (!pendingRefresh.current) {
      const refreshToken = refreshTokenRef.current
      pendingRefresh.current = (async () => {
        if (!refreshToken) throw new ApiError(401, 'No hay refresh token', null)
        const pair = await apiFetch<TokenPair>('/api/auth/refresh', {
          method: 'POST',
          body: JSON.stringify({ refreshToken }),
        })
        saveTokens(pair)
        return pair.accessToken
      })().finally(() => {
        pendingRefresh.current = null
      })
    }
    return pendingRefresh.current
  }, [saveTokens])

  const authFetch = useCallback(
    async <T,>(path: string, init: RequestInit = {}): Promise<T> => {
      try {
        return await apiFetch<T>(path, init, { token: accessTokenRef.current })
      } catch (err) {
        // Solo reintentamos ante 401; un 403 o 429 no se arregla renovando el token.
        if (!(err instanceof ApiError) || err.status !== 401 || !refreshTokenRef.current) throw err
      }

      let newAccessToken: string
      try {
        newAccessToken = await renewSession()
      } catch (refreshError) {
        clearSession() // refresh vencido, revocado o reutilizado: hay que volver a iniciar sesión
        throw refreshError
      }

      // Reintento ÚNICO: si vuelve a fallar con 401, cerramos sesión y no reintentamos más.
      return apiFetch<T>(path, init, { token: newAccessToken, onUnauthorized: clearSession })
    },
    [renewSession, clearSession],
  )

  const value = useMemo<AuthContextValue>(
    () => ({ token, isAuthenticated: token !== null, login: saveTokens, logout, authFetch }),
    [token, saveTokens, logout, authFetch],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth debe usarse dentro de <AuthProvider>')
  return ctx
}

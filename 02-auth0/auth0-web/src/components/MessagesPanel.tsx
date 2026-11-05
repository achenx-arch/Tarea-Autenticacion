import { useAuth0 } from '@auth0/auth0-react'
import { useCallback, useEffect, useState } from 'react'
import { config } from '../config'
import { decodeJwt } from '../lib/jwt'

interface Message {
  id: number
  text: string
  createdBy: string
}

/*
 * Lista de mensajes con botón "Eliminar".
 *
 * El botón solo se muestra si el access token trae "delete:messages" en el claim permissions.
 * OJO: esto es solo EXPERIENCIA DE USUARIO, no seguridad. Cualquiera puede llamar
 * DELETE /api/messages/{id} con Postman o curl; quien realmente decide es la API
 * con la política "delete:messages" (responde 403 a un Lector).
 */
export default function MessagesPanel() {
  const { getAccessTokenSilently } = useAuth0()
  const [messages, setMessages] = useState<Message[]>([])
  const [permissions, setPermissions] = useState<string[]>([])
  const [status, setStatus] = useState<{ ok: boolean; text: string } | null>(null)
  const [busy, setBusy] = useState(false)

  const canDelete = permissions.includes('delete:messages')

  const loadMessages = useCallback(async () => {
    setBusy(true)
    try {
      const token = await getAccessTokenSilently()
      if (!token) throw new Error('No se obtuvo el access token')
      // Leemos los permisos del access token (solo para decidir qué mostrar).
      setPermissions(decodeJwt(token)?.payload.permissions ?? [])

      const response = await fetch(`${config.apiUrl}/api/messages`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      setStatus({ ok: response.ok, text: `GET /api/messages → HTTP ${response.status}` })
      setMessages(response.ok ? await response.json() : [])
    } catch (err) {
      setStatus({ ok: false, text: err instanceof Error ? err.message : String(err) })
    } finally {
      setBusy(false)
    }
  }, [getAccessTokenSilently])

  async function deleteMessage(id: number) {
    setBusy(true)
    try {
      const token = await getAccessTokenSilently()
      const response = await fetch(`${config.apiUrl}/api/messages/${id}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      })
      setStatus({ ok: response.ok, text: `DELETE /api/messages/${id} → HTTP ${response.status}` })
      if (response.ok) setMessages((current) => current.filter((m) => m.id !== id))
    } catch (err) {
      setStatus({ ok: false, text: err instanceof Error ? err.message : String(err) })
    } finally {
      setBusy(false)
    }
  }

  useEffect(() => {
    void loadMessages()
  }, [loadMessages])

  return (
    <section className="card">
      <h2>Mensajes</h2>
      <p className="muted">
        Tus permisos: <code>{JSON.stringify(permissions)}</code> · Rol detectado:{' '}
        <strong>{canDelete ? 'Administrador' : permissions.includes('read:messages') ? 'Lector' : 'Sin rol'}</strong>
      </p>

      <div className="actions">
        <button onClick={loadMessages} disabled={busy}>
          Recargar mensajes
        </button>
      </div>

      {status && <p className={`alert ${status.ok ? 'ok' : 'error'}`}>{status.text}</p>}

      <table>
        <thead>
          <tr>
            <th>Id</th>
            <th>Texto</th>
            <th>Creado por</th>
            {canDelete && <th></th>}
          </tr>
        </thead>
        <tbody>
          {messages.map((m) => (
            <tr key={m.id}>
              <td>{m.id}</td>
              <td>{m.text}</td>
              <td>{m.createdBy}</td>
              {canDelete && (
                <td>
                  <button className="secondary" disabled={busy} onClick={() => deleteMessage(m.id)}>
                    Eliminar
                  </button>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
      {messages.length === 0 && <p className="muted">No hay mensajes para mostrar.</p>}
    </section>
  )
}

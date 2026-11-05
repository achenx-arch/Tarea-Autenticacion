import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext'

export default function Layout() {
  const { isAuthenticated, logout } = useAuth()
  const navigate = useNavigate()

  // Cerrar sesión llama a POST /api/auth/logout para revocar el refresh token en el servidor.
  async function handleLogout() {
    await logout()
    navigate('/login')
  }

  return (
    <>
      <header className="navbar">
        <strong>🔐 Demo Auth · Local</strong>
        <nav>
          <NavLink to="/" end>
            Inicio
          </NavLink>
          {isAuthenticated ? (
            <>
              <NavLink to="/perfil">Perfil</NavLink>
              <NavLink to="/seguridad">Seguridad</NavLink>
              <button onClick={handleLogout}>Cerrar sesión</button>
            </>
          ) : (
            <>
              <NavLink to="/registro">Registro</NavLink>
              <NavLink to="/login">Iniciar sesión</NavLink>
            </>
          )}
        </nav>
      </header>
      <main className="container">
        <Outlet />
      </main>
    </>
  )
}

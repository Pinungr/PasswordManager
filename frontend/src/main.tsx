import '@fontsource-variable/inter/wght.css'
import { Eye, EyeOff, ShieldCheck } from 'lucide-react'
import { lazy, StrictMode, Suspense, useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { useForm } from 'react-hook-form'
import { BrowserRouter } from 'react-router-dom'
import { z } from 'zod'
import { Button } from './components/ui/Button'
import { api } from './services/api'
import './styles.css'

const PersonalWorkspace = lazy(() => import('./vault/PersonalVault').then(({ PersonalWorkspace }) =>
  ({ default: PersonalWorkspace })))

interface Session {
  id: string
  username: string
  full_name: string
  role: 'ADMIN' | 'TEAM_LEAD' | 'MEMBER'
  must_change: boolean
  csrf: string
  expires_at: number
}

type Form = { username?: string; full_name?: string; current_password?: string; password: string; confirm?: string }
const loginSchema = z.object({ username: z.string().min(3), password: z.string().min(1) })
const signupSchema = z.object({
  username: z.string().min(3).max(64).regex(/^[a-zA-Z0-9._-]+$/),
  full_name: z.string().trim().min(1).max(200),
  password: z.string().min(8),
})
const changeSchema = z.object({ current_password: z.string().min(1), password: z.string().min(8) })

function AccountForm({ session, signingUp, onSession }: {
  session: Session | null
  signingUp: boolean
  onSession: (value: Session) => void
}) {
  const [visible, show] = useState(false)
  const [error, setError] = useState('')
  const { register, handleSubmit, formState: { isSubmitting } } = useForm<Form>()
  const editing = session !== null

  const submit = handleSubmit(async (values) => {
    setError('')
    const parsed = (editing ? changeSchema : signingUp ? signupSchema : loginSchema).safeParse(values)
    if (!parsed.success) {
      setError(editing ? 'Enter your current password and a new password of at least 8 characters.'
        : signingUp ? 'Enter your name, a valid username, and a password of at least 8 characters.'
          : 'Enter your username and password.')
      return
    }
    if (signingUp && values.password !== values.confirm) {
      setError('Account passwords do not match.')
      return
    }
    try {
      const path = editing ? 'auth/password' : signingUp ? 'auth/signup' : 'auth/login'
      onSession(await api<Session>(path, parsed.data, session?.csrf))
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Request failed.')
    }
  })
  return (
    <form onSubmit={submit} className="account-form">
      {signingUp && <label>Full name<input autoComplete="name" required maxLength={200}
        {...register('full_name')} /></label>}
      {editing ? <label>Current account password<input type="password" autoComplete="current-password"
        required {...register('current_password')} /></label>
        : <label>Username<input autoCapitalize="none" autoComplete="username"
          minLength={signingUp ? 3 : undefined} maxLength={64}
          pattern={signingUp ? String.raw`[a-zA-Z0-9._\-]+` : undefined}
          title={signingUp ? 'Use letters, numbers, periods, underscores or hyphens.' : undefined}
          required {...register('username')} /></label>}
      <label>{editing ? 'New account password' : 'Password'}
        <span className="password-input">
          <input type={visible ? 'text' : 'password'} required
            minLength={editing || signingUp ? 8 : undefined} maxLength={512}
            autoComplete={editing || signingUp ? 'new-password' : 'current-password'} {...register('password')} />
          <button type="button" className="show-password" aria-label={visible ? 'Hide password' : 'Show password'}
            onClick={() => show(!visible)}>{visible ? <EyeOff size={18} /> : <Eye size={18} />}</button>
        </span>
      </label>
      {signingUp && <label>Confirm account password<input type="password" autoComplete="new-password"
        required maxLength={512} {...register('confirm')} /></label>}
      {error && <p className="error" role="alert">{error}</p>}
      <Button type="submit" disabled={isSubmitting}>
        {isSubmitting ? 'Submitting…' : editing ? 'Update password' : signingUp ? 'Create account' : 'Sign in'}
      </Button>
    </form>
  )
}

function App() {
  const [session, setSession] = useState<Session | null>(null)
  const [loading, setLoading] = useState(true)
  const [editing, setEditing] = useState(false)
  const [signup, setSignup] = useState(false)
  const [error, setError] = useState('')
  useEffect(() => {
    let cancelled = false
    fetch('/api/v1/auth/session').then(async (response) => {
      if (response.status === 401) return null
      if (!response.ok) throw new Error()
      return await response.json() as Session
    }).then((value) => {
      if (!cancelled) setSession(value)
    }).catch(() => {
      if (!cancelled) setError('The service is unavailable.')
    }).finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [])
  useEffect(() => {
    const expire = () => { setSession(null); setEditing(false); setError('Session expired. Sign in again.') }
    window.addEventListener('securevault:session-expired', expire)
    return () => window.removeEventListener('securevault:session-expired', expire)
  }, [])
  useEffect(() => {
    if (!session) return
    const expire = () => {
      if (Date.now() >= session.expires_at * 1000) window.dispatchEvent(new Event('securevault:session-expired'))
    }
    const timer = window.setInterval(expire, 1000)
    document.addEventListener('visibilitychange', expire)
    expire()
    return () => {
      window.clearInterval(timer)
      document.removeEventListener('visibilitychange', expire)
    }
  }, [session])
  const change = Boolean(session?.must_change || editing)
  const signingUp = !session && signup
  async function logout() {
    if (!session) return
    setSession(null)
    setEditing(false)
    try {
      await api('auth/logout', {}, session.csrf)
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Sign-out failed.')
    }
  }
  if (session && !change && !loading) {
    return <Suspense fallback={<main className="account-page"><p role="status">Loading vault…</p></main>}>
      <PersonalWorkspace account={session} logout={() => void logout()} settings={() => setEditing(true)} />
    </Suspense>
  }
  return (
    <main className="account-page">
      <section className="account-card">
        <div className="brand-mark"><ShieldCheck aria-hidden="true" size={25} /></div>
        <h1>{change ? 'Change account password' : signingUp ? 'Create your account' : 'Pinaki SecureVault'}</h1>
        <p className="account-description">
          {change ? 'Choose a new password to continue.'
            : signingUp ? 'Create an account for your personal vault.' : 'Sign in to your vault.'}
        </p>
        {error && <p className="error" role="alert">{error}</p>}
        {loading ? <p role="status">Checking session…</p> : !session || change ?
          <AccountForm key={change ? 'change' : signingUp ? 'signup' : 'login'} session={session}
            signingUp={signingUp} onSession={(next) => {
            setSession(next)
            setEditing(false)
            setSignup(false)
            setError('')
          }} />
          : null}
        {!loading && !session && <button className="secondary logout" type="button" onClick={() => {
          setError('')
          setSignup(!signingUp)
        }}>{signingUp ? 'Back to sign in' : 'Create an account'}</button>}
        {session && <button className="secondary logout" type="button" onClick={() => void logout()}>Sign out</button>}
      </section>
      <footer>Pinaki SecureVault · 1.0.0</footer>
    </main>
  )
}

const persistedTheme = localStorage.getItem('securevault-theme')
if (persistedTheme === 'light' || persistedTheme === 'dark' || persistedTheme === 'system') {
  document.documentElement.dataset.theme = persistedTheme
} else {
  document.documentElement.dataset.theme = 'light'
  void api<{ theme: string }>('info').then(({ theme }) => {
    if (!localStorage.getItem('securevault-theme')) document.documentElement.dataset.theme = theme
  }).catch(() => {})
}
const root = document.getElementById('root')
if (root) createRoot(root).render(<StrictMode><BrowserRouter><App /></BrowserRouter></StrictMode>)

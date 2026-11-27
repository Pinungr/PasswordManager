import { useEffect, useState } from 'react'
import type { FormEvent, ReactNode } from 'react'
import { api } from '../services/api'

type Account = { id: string; role: string; csrf: string }
type User = { id: string; username: string; full_name: string; email: string | null; role: string
  active: boolean; created_at: number; last_login: number | null; teams: string[] }
type Team = { id: string; name: string; description: string; lead_id: string | null
  active: boolean; member_count: number }
type Member = Pick<User, 'id' | 'username' | 'full_name' | 'active'>
type Catalog = { id: string; name: string; description: string; appearance: string; active: boolean }
type Settings = { profile: { username: string; full_name: string; email: string | null; role: string }
  policy: Record<string, number | string> | null }
type Audit = { id: number; timestamp: number; user: string; action: string; type: string
  target: unknown; result: string; source: string | null }
const formattedDate = (epoch: number | null) => epoch ? new Date(epoch * 1000).toLocaleString() : '—'
const errorMessage = (error: unknown) => error instanceof Error ? error.message : 'Request failed.'
const value = (form: FormData, key: string) => String(form.get(key) ?? '')
const roles = ['ADMIN', 'TEAM_LEAD', 'MEMBER']
const policyLabels: Record<string, string> = {
  account_password_min_length: 'Minimum account password length', max_registered_users: 'Maximum registered users', session_timeout_minutes: 'Session timeout (minutes)',
  vault_auto_lock_minutes: 'Vault auto-lock (minutes)', secret_reveal_timeout_seconds: 'Secret reveal (seconds)',
  clipboard_clear_seconds: 'Clipboard clear (seconds)', max_login_attempts: 'Maximum login attempts',
  login_lockout_minutes: 'Login lockout (minutes)', password_history_limit: 'Credential versions retained',
  recycle_bin_retention_days: 'Recycle bin retention (days)', backup_retention_days: 'Backup retention (days)',
  backup_schedule: 'Daily backup time',
}

function useRemote<T>(path: string) {
  const [data, setData] = useState<T>()
  const [error, setError] = useState('')
  const [serial, setSerial] = useState(0)
  useEffect(() => {
    let active = true
    setError('')
    void api<T>(path).then((response) => { if (active) setData(response) })
      .catch((error) => { if (active) setError(errorMessage(error)) })
    return () => { active = false }
  }, [path, serial])
  return { data, error, reload: () => setSerial((item) => item + 1) }
}

function Status({ error, data }: { error: string; data: unknown }) {
  return error ? <p className="error" role="alert">{error}</p>
    : data === undefined ? <p role="status">Loading…</p> : null
}

function Table({ headers, children }: { headers: string[]; children: ReactNode }) {
  return <div className="table-wrap"><table>
    <thead><tr>{headers.map((item) => <th key={item} scope="col">{item}</th>)}</tr></thead>
    <tbody>{children}</tbody>
  </table></div>
}

function useMutation(refresh: () => void) {
  const [busy, setBusy] = useState(false)
  const [status, setStatus] = useState('')
  const [failed, setFailed] = useState(false)
  async function run(work: () => Promise<unknown>, success = 'Changes saved.') {
    if (busy) return
    setBusy(true); setStatus(''); setFailed(false)
    try { await work(); setStatus(success); refresh() }
    catch (error) { setStatus(errorMessage(error)); setFailed(true) }
    finally { setBusy(false) }
  }
  return { busy, run, output: status && <p className={failed ? 'error' : 'muted'}
    role={failed ? 'alert' : 'status'}>{status}</p> }
}

export function UsersScreen({ account }: { account: Account }) {
  const list = useRemote<{ items: User[]; capacity: number }>('users')
  const teams = useRemote<Team[]>('teams')
  const action = useMutation(list.reload)
  const [editing, edit] = useState<User | 'new' | null>(null)
  const [reset, setReset] = useState<User | 'private' | null>(null)
  const [assign, setAssign] = useState<User | null>(null)
  const [search, setSearch] = useState('')
  const active = list.data?.items.filter((user) => user.active).length ?? 0
  const filtered = list.data?.items.filter((user) =>
    [user.username, user.full_name, user.email].join(' ').toLowerCase().includes(search.toLowerCase())) ?? []

  function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    const fields = { full_name: value(form, 'full_name'), email: value(form, 'email') || null,
      role: value(form, 'role'), active: form.has('active') }
    void action.run(async () => {
      if (editing === 'new') await api('users', { ...fields, username: value(form, 'username'),
        password: value(form, 'password'), team_ids: form.getAll('team') }, account.csrf)
      else if (editing) await api('users/' + editing.id, fields, account.csrf, 'PUT')
      edit(null)
    })
  }

  return <div className="admin-stack">
    <Status error={list.error} data={list.data} />
    {list.data && <>
      <div className="metrics">{[
        ['Managed users', list.data.items.length], ['Maximum capacity', list.data.capacity],
        ['Active users', active], ['Inactive users', list.data.items.length - active],
      ].map(([name, count]) => <div key={name} className="vault-panel metric"><span>{name}</span><strong>{count}</strong></div>)}</div>
      <section className="vault-panel admin-stack">
        <div className="list-head"><h2>Users</h2><div className="actions">
          <button className="secondary" onClick={() => { setReset('private'); edit(null); setAssign(null) }}>
            Reset private account password
          </button>
          <button className="primary" onClick={() => { edit('new'); setReset(null); setAssign(null) }}>Create user</button>
        </div></div>
        <input aria-label="Search users" type="search" placeholder="Search users" value={search}
          onChange={(event) => setSearch(event.target.value)} />
        <Table headers={['User', 'Role', 'Teams', 'Status', 'Created', 'Last login', 'Actions']}>
          {filtered.map((user) => <tr key={user.id}>
            <td><strong>{user.full_name}</strong><small>{user.username} {user.email ? ' · ' + user.email : ''}</small></td>
            <td>{user.role}</td><td>{user.teams.map((id) => teams.data?.find((team) => team.id === id)?.name ?? '').filter(Boolean).join(', ') || '—'}</td>
            <td>{user.active ? 'Active' : 'Inactive'}</td><td>{formattedDate(user.created_at)}</td><td>{formattedDate(user.last_login)}</td>
            <td><div className="actions"><button className="secondary" onClick={() => { edit(user); setReset(null); setAssign(null) }}>Edit</button>
              <button className="secondary" onClick={() => { setAssign(user); edit(null); setReset(null) }}>Assign teams</button>
              {user.id !== account.id && <button className="secondary" onClick={() => { setReset(user); edit(null); setAssign(null) }}>Reset password</button>}</div></td>
          </tr>)}
        </Table>
        {!filtered.length && <p className="muted">No users match your search.</p>}
      </section>
    </>}
    {editing && <form className="vault-panel editor admin-form" key={editing === 'new' ? 'new' : editing.id} onSubmit={save}>
      <h2>{editing === 'new' ? 'Create user' : 'Edit user'}</h2>
      {editing === 'new' && <label>Username<input name="username" required minLength={3} maxLength={64} /></label>}
      <label>Full name<input name="full_name" defaultValue={editing === 'new' ? '' : editing.full_name} required maxLength={200} /></label>
      <label>Email<input name="email" type="email" defaultValue={editing === 'new' ? '' : editing.email ?? ''} /></label>
      {editing === 'new' && <label>Temporary password<input name="password" autoComplete="new-password" type="password" minLength={8} required /></label>}
      <label>Role<select name="role" defaultValue={editing === 'new' ? 'MEMBER' : editing.role}>
        {roles.map((role) => <option key={role}>{role}</option>)}</select></label>
      <label className="checkbox"><input name="active" type="checkbox" defaultChecked={editing === 'new' || editing.active} /> Active</label>
      {editing === 'new' && teams.data && teams.data.some((team) => team.active) && <fieldset className="editor">
        <legend>Teams</legend>{teams.data.filter((team) => team.active).map((team) =>
          <label className="checkbox" key={team.id}><input name="team" type="checkbox" value={team.id} /> {team.name}</label>)}
      </fieldset>}
      <div className="actions"><button className="primary" disabled={action.busy}>Save user</button><button type="button" className="secondary" onClick={() => edit(null)}>Cancel</button></div>
    </form>}
    {assign && <form className="vault-panel editor admin-form" onSubmit={(event) => {
      event.preventDefault()
      const values = new FormData(event.currentTarget).getAll('team')
      if (assign.teams.some((team) => !values.includes(team)) &&
        !window.confirm('Remove these team memberships and revoke their shared vault grants?')) return
      void action.run(async () => {
        await api('users/' + assign.id + '/teams', { team_ids: values }, account.csrf, 'PUT')
        setAssign(null)
      })
    }}>
      <h2>Assign teams · {assign.full_name}</h2>
      {teams.data?.filter((team) => team.active || assign.teams.includes(team.id)).map((team) =>
        <label className="checkbox" key={team.id}><input name="team" type="checkbox" value={team.id}
          defaultChecked={assign.teams.includes(team.id)} /> {team.name}</label>)}
      <div className="actions"><button className="primary" disabled={action.busy}>Save teams</button>
        <button type="button" className="secondary" onClick={() => setAssign(null)}>Cancel</button></div>
    </form>}
    {reset && <form className="vault-panel editor admin-form" key={reset === 'private' ? reset : reset.id} onSubmit={(event) => {
      event.preventDefault()
      const form = new FormData(event.currentTarget)
      const password = value(form, 'password')
      if (!window.confirm('Reset this account password and end its active sessions?')) return
      void action.run(async () => {
        if (reset === 'private') {
          await api('users/private-password-reset', { username: value(form, 'username'), password }, account.csrf)
        } else {
          await api('users/' + reset.id + '/password-reset', { password }, account.csrf)
        }
        setReset(null)
      }, reset === 'private' ? 'If the username matches a private account, its temporary password has been set.' : undefined)
    }}><h2>{reset === 'private' ? 'Reset private account password' : 'Reset account password'}</h2>
      {reset === 'private' ? <>
        <p>Ask the account owner for their username. They must replace the temporary password when they sign in.</p>
        <label>Username<input name="username" autoCapitalize="none" required minLength={3} maxLength={64} /></label>
      </> : <p>{reset.full_name}</p>}
      <label>Temporary password<input name="password" type="password" autoComplete="new-password" required minLength={8} maxLength={512} /></label>
      <div className="actions"><button className="primary" disabled={action.busy}>Reset password</button>
        <button type="button" className="secondary" onClick={() => setReset(null)}>Cancel</button></div>
    </form>}
    {action.output}
  </div>
}

function TeamMembers({ account, team, close }: { account: Account; team: Team; close: () => void }) {
  const list = useRemote<Member[]>('teams/' + team.id + '/members')
  const action = useMutation(list.reload)
  return <section className="vault-panel admin-stack">
    <div className="list-head"><h2>{team.name} members</h2><button className="secondary" onClick={close}>Close</button></div>
    <Status data={list.data} error={list.error} />
    {list.data?.map((member) => <div key={member.id} className="list-head">
      <span>{member.full_name} <small className="muted">{member.username}</small></span>
      {member.id !== team.lead_id && <button className="secondary" disabled={action.busy} onClick={() => {
        if (window.confirm('Remove this user from the team and revoke shared vault access?')) void action.run(() =>
          api('teams/' + team.id + '/members/' + member.id, undefined, account.csrf, 'DELETE'))
      }}>Remove member</button>}
    </div>)}
    <form className="actions" onSubmit={(event) => {
      event.preventDefault()
      const form = event.currentTarget
      const username = value(new FormData(form), 'username')
      void action.run(async () => { await api('teams/' + team.id + '/members', { username }, account.csrf); form.reset() })
    }}>
      <label>Existing username<input name="username" required /></label>
      <button className="primary" disabled={action.busy}>Add member</button>
    </form>
    {action.output}
  </section>
}

export function TeamsScreen({ account }: { account: Account }) {
  const teams = useRemote<Team[]>('teams')
  const [leads, setLeads] = useState<User[]>([])
  const action = useMutation(teams.reload)
  const [editing, edit] = useState<Team | 'new' | null>(null)
  const [members, setMembers] = useState<Team | null>(null)
  const admin = account.role === 'ADMIN'
  useEffect(() => {
    if (admin) void api<{ items: User[] }>('users').then((data) =>
      setLeads(data.items.filter((user) => user.active && user.role === 'TEAM_LEAD'))).catch(() => {})
  }, [admin])

  return <div className="admin-stack">
    <Status error={teams.error} data={teams.data} />
    <section className="vault-panel admin-stack">
      <div className="list-head"><h2>Teams</h2>{admin && <button className="primary" onClick={() => edit('new')}>Create team</button>}</div>
      <Table headers={['Team', 'Team lead', 'Members', 'Status', 'Actions']}>
        {teams.data?.map((team) => <tr key={team.id}>
          <td><strong>{team.name}</strong><small>{team.description}</small></td>
          <td>{leads.find((lead) => lead.id === team.lead_id)?.full_name ?? (team.lead_id === account.id ? 'You' : '—')}</td>
          <td>{team.member_count}</td><td>{team.active ? 'Active' : 'Inactive'}</td>
          <td>{(admin || team.lead_id === account.id) && <div className="actions">
            <button className="secondary" onClick={() => edit(team)}>Edit</button>
            <button className="secondary" onClick={() => setMembers(team)}>Members</button>
          </div>}</td>
        </tr>)}
      </Table>
      {teams.data?.length === 0 && <p className="muted">No teams available.</p>}
    </section>
    {editing && <form className="vault-panel editor admin-form" key={editing === 'new' ? 'new' : editing.id}
      onSubmit={(event) => {
        event.preventDefault()
        const form = new FormData(event.currentTarget)
        const body = { name: value(form, 'name'), description: value(form, 'description'),
          lead_id: admin ? value(form, 'lead') || null : editing === 'new' ? null : editing.lead_id,
          active: admin ? form.has('active') : editing === 'new' || editing.active }
        void action.run(async () => {
          await api(editing === 'new' ? 'teams' : 'teams/' + editing.id, body, account.csrf, editing === 'new' ? 'POST' : 'PUT')
          edit(null)
        })
      }}>
      <h2>{editing === 'new' ? 'Create team' : 'Edit team'}</h2>
      <label>Team name<input name="name" required defaultValue={editing === 'new' ? '' : editing.name} maxLength={100} /></label>
      <label>Description<textarea name="description" defaultValue={editing === 'new' ? '' : editing.description} maxLength={1000} /></label>
      {admin && <><label>Team lead<select name="lead" defaultValue={editing === 'new' ? '' : editing.lead_id ?? ''}>
        <option value="">Unassigned</option>{leads.map((lead) => <option key={lead.id} value={lead.id}>{lead.full_name}</option>)}
      </select></label><label className="checkbox"><input name="active" type="checkbox" defaultChecked={editing === 'new' || editing.active} /> Active</label></>}
      <div className="actions"><button className="primary" disabled={action.busy}>Save team</button><button type="button" className="secondary" onClick={() => edit(null)}>Cancel</button></div>
    </form>}
    {members && <TeamMembers account={account} team={members} close={() => { setMembers(null); teams.reload() }} />}
    {action.output}
  </div>
}

export function CatalogScreen({ account, kind }: { account: Account; kind: 'categories' | 'environments' }) {
  const list = useRemote<Catalog[]>('catalog/' + kind)
  const action = useMutation(list.reload)
  const [editing, edit] = useState<Catalog | 'new' | null>(null)
  const env = kind === 'environments'
  const singular = env ? 'environment' : 'category'
  return <div className="admin-stack">
    <Status data={list.data} error={list.error} />
    <section className="vault-panel admin-stack">
      <div className="list-head"><h2>{env ? 'Environments' : 'Categories'}</h2>
        <button className="primary" onClick={() => edit('new')}>Add {singular}</button></div>
      <Table headers={['Name', 'Description', env ? 'Color' : 'Icon', 'Status', 'Actions']}>
        {list.data?.map((item) => <tr key={item.id}><td><strong>{item.name}</strong></td><td>{item.description || '—'}</td>
          <td>{item.appearance}</td><td>{item.active ? 'Active' : 'Inactive'}</td>
          <td><button className="secondary" onClick={() => edit(item)}>Edit</button></td></tr>)}
      </Table>
    </section>
    {editing && <form className="vault-panel editor admin-form" key={editing === 'new' ? 'new' : editing.id} onSubmit={(event) => {
      event.preventDefault()
      const form = new FormData(event.currentTarget)
      void action.run(async () => {
        await api('catalog/' + kind + (editing === 'new' ? '' : '/' + editing.id), {
          name: value(form, 'name'), description: value(form, 'description'),
          appearance: value(form, 'appearance'), active: form.has('active'),
        }, account.csrf, editing === 'new' ? 'POST' : 'PUT')
        edit(null)
      })
    }}>
      <h2>{editing === 'new' ? 'Add ' : 'Edit '}{singular}</h2>
      <label>Name<input name="name" defaultValue={editing === 'new' ? '' : editing.name} required /></label>
      <label>Description<textarea name="description" defaultValue={editing === 'new' ? '' : editing.description} /></label>
      {env ? <label>Color<input name="appearance" type="color" defaultValue={editing === 'new' ? '#2563eb' : editing.appearance} /></label>
        : <label>Icon<select name="appearance" defaultValue={editing === 'new' ? 'key' : editing.appearance}>
          {['key', 'database', 'globe', 'terminal', 'file'].map((icon) => <option key={icon}>{icon}</option>)}</select></label>}
      <label className="checkbox"><input name="active" type="checkbox" defaultChecked={editing === 'new' || editing.active} /> Active</label>
      <div className="actions"><button className="primary" disabled={action.busy}>Save {singular}</button>
        <button type="button" className="secondary" onClick={() => edit(null)}>Cancel</button></div>
    </form>}
    {action.output}
  </div>
}

export function AuditScreen() {
  const [query, setQuery] = useState('')
  const [cursor, setCursor] = useState(0)
  const list = useRemote<{ items: Audit[]; cursor: number | null }>('audit?' + query + '&cursor=' + cursor)
  return <section className="vault-panel admin-stack">
    <form className="metadata-grid" onSubmit={(event) => {
      event.preventDefault()
      const params = new URLSearchParams()
      const form = new FormData(event.currentTarget)
      for (const field of ['action', 'username', 'result', 'type']) if (value(form, field)) params.set(field, value(form, field))
      for (const field of ['since', 'until']) if (value(form, field)) params.set(field,
        String(new Date(value(form, field) + 'T00:00:00').getTime() / 1000 + (field === 'until' ? 86400 : 0)))
      setQuery(params.toString()); setCursor(0)
    }}>
      <label>From<input type="date" name="since" /></label><label>Through<input type="date" name="until" /></label>
      <label>Username<input name="username" maxLength={64} /></label><label>Action<input name="action" maxLength={80} /></label>
      <label>Event type<select name="type"><option value="">All</option><option value="server">Server</option><option value="client">Client-reported</option></select></label>
      <label>Result<select name="result"><option value="">All</option><option>success</option><option>failure</option></select></label>
      <button className="primary">Apply filters</button>
      <a className="secondary" href={'/api/v1/audit?export=true&' + query}>Export audit CSV</a>
    </form>
    <Status data={list.data} error={list.error} />
    <Table headers={['Timestamp', 'User', 'Action', 'Resource', 'Event type', 'Result', 'Source IP']}>
      {list.data?.items.map((event) => <tr key={event.id}><td>{formattedDate(event.timestamp)}</td><td>{event.user || '—'}</td>
        <td>{event.action}</td><td>{event.target ? String(event.target) : '—'}</td><td>{event.type}</td>
        <td>{event.result}</td><td>{event.source || '—'}</td></tr>)}
    </Table>
    {list.data?.items.length === 0 && <p className="muted">No matching audit events.</p>}
    <div className="actions">
      {cursor !== 0 && <button className="secondary" onClick={() => setCursor(0)}>Newest events</button>}
      {list.data?.cursor && <button className="secondary" onClick={() => setCursor(list.data!.cursor!)}>Older events</button>}
    </div>
  </section>
}

export function SettingsScreen({ account, password, master, profileOnly }: {
  account: Account; password: () => void; master: () => void; profileOnly: boolean
}) {
  const settings = useRemote<Settings>('settings')
  const action = useMutation(settings.reload)
  const [theme, setTheme] = useState(document.documentElement.dataset.theme ?? 'system')
  return <div className="admin-stack">
    <Status data={settings.data} error={settings.error} />
    {settings.data && <form className="vault-panel editor admin-form" onSubmit={(event) => {
      event.preventDefault(); const form = new FormData(event.currentTarget)
      void action.run(() => api('settings/profile', {
        full_name: value(form, 'full_name'), email: value(form, 'email') || null,
      }, account.csrf, 'PUT'))
    }}>
      <h2>My profile</h2><p className="muted">{settings.data.profile.username} · {settings.data.profile.role}</p>
      <label>Full name<input name="full_name" required defaultValue={settings.data.profile.full_name} /></label>
      <label>Email<input name="email" type="email" defaultValue={settings.data.profile.email ?? ''} /></label>
      <button className="primary fit" disabled={action.busy}>Save profile</button>
    </form>}
    {!profileOnly && <>
      <section className="vault-panel editor admin-form"><h2>Account and vault</h2>
        <div className="actions"><button className="secondary" onClick={password}>Change account password</button>
          <button className="secondary" onClick={master}>Change vault master password</button></div>
        <label>Appearance<select value={theme} onChange={(event) => {
          const selected = event.target.value
          setTheme(selected); document.documentElement.dataset.theme = selected
          localStorage.setItem('securevault-theme', selected)
        }}><option value="system">System</option><option value="light">Light</option><option value="dark">Dark</option></select></label>
      </section>
      {settings.data?.policy && <form className="vault-panel editor admin-form" onSubmit={(event) => {
        event.preventDefault(); const form = new FormData(event.currentTarget)
        const policy = Object.fromEntries(Object.entries(settings.data!.policy!).map(([name, type]) =>
          [name, typeof type === 'number' ? Number(value(form, name)) : value(form, name)]))
        void action.run(() => api('settings/policy', policy, account.csrf, 'PUT'))
      }}>
        <h2>Security policy</h2>
        <div className="metadata-grid">{Object.entries(settings.data.policy).map(([field, defaultValue]) =>
          <label key={field}>{policyLabels[field] ?? field}<input name={field} type={typeof defaultValue === 'number' ? 'number' : 'time'}
            min={typeof defaultValue === 'number' ? 1 : undefined} required defaultValue={defaultValue} /></label>)}</div>
        <p className="muted">Policy changes apply to subsequent requests and password changes.</p>
        <button className="primary fit" disabled={action.busy}>Save policy</button>
      </form>}
      <section className="vault-panel"><h2>Application information</h2><p className="muted">Pinaki SecureVault · 1.0.0</p></section>
    </>}
    {action.output}
  </div>
}

import { Activity, Bell, Clock3, Copy, DatabaseBackup, Eye, FileUp, FolderLock, Globe, KeyRound,
  LayoutDashboard, LockKeyhole, LogOut, PanelLeft, Plus, Settings, ShieldCheck, Star, SunMoon,
  Tags, Timer, Trash2, User, Users, WandSparkles } from 'lucide-react'
import { useCallback, useEffect, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Button } from '../components/ui/Button'
import { HttpTestMode } from '../components/ui/HttpTestMode'
import { randomUuid } from '../crypto/browser'
import { generateVaultRoot, importVaultRoot, openRecord, sealRecord } from '../crypto/record'
import type { VaultRoot } from '../crypto/record'
import { newVaultKeys, openVault } from '../crypto/vault'
import type { PersonalVault as Vault } from '../crypto/vault'
import { api } from '../services/api'
import { blank, credential } from './data'
import type { CatalogEntry, Credential, Limits, VaultRecord, WireRecord } from './data'
import { AuditScreen, CatalogScreen, SettingsScreen, TeamsScreen, UsersScreen } from './AdminScreens'
import { Backups } from './Backups'
import { CsvImport } from './CsvImport'
import { Editor } from './Editor'
import { Dashboard, daysRemaining, Expiry, PasswordHealth } from './Insights'
import { Generator } from './Generator'
import { SharedVaults } from './SharedVaults'
import type { SharedVault } from './SharedVaults'

type Account = { id: string; full_name: string; csrf: string; role: string }
type VaultInfo = { vault: Vault | null; limits: Limits }
const date = (seconds: number) => new Date(seconds * 1000).toLocaleDateString()
const navIcons = {
  'Dashboard': LayoutDashboard, 'My vault': KeyRound, 'Favorites': Star, 'Recently used': Clock3,
  'Expiring secrets': Timer, 'Password health': Activity, 'Password generator': WandSparkles,
  'Recycle bin': Trash2, 'CSV import': FileUp, 'Users': Users, 'Teams': Users, 'Environments': Globe,
  'Categories': Tags, 'Audit logs': Activity, 'Backup & restore': DatabaseBackup, 'Application settings': Settings,
} as const
const fail = (error: unknown) => error instanceof Error ? error.message : 'Request failed.'

async function decrypt(root: VaultRoot, vaultId: string, wire: WireRecord, epoch?: number): Promise<VaultRecord> {
  const bytes = await openRecord(root, { vaultId, recordId: wire.id, version: wire.crypto_version, epoch }, wire.payload)
  try {
    return { ...wire, value: credential.parse(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))) }
  } finally {
    bytes.fill(0)
  }
}

function VaultGate({ info, account, unlocked, created, changing, cancelChange }: {
  info: VaultInfo
  account: Account
  unlocked: (key: VaultRoot) => void
  created: (vault: Vault) => void
  changing: boolean
  cancelChange: () => void
}) {
  const [recover, setRecover] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [pending, setPending] = useState<{ key: VaultRoot; code: string } | null>(null)
  const creating = info.vault === null
  const recovering = !creating && recover
  const replacing = recovering || changing

  async function submit(form: FormData) {
    const input = String(form.get('master') ?? '')
    const newPassword = creating ? input : String(form.get('next') ?? '')
    setError('')
    if ((creating || replacing) &&
      (newPassword.length < 8 || newPassword !== form.get('confirm') || !newPassword.trim())) {
      setError('Enter a matching vault master password of at least 8 characters.')
      return
    }
    setBusy(true)
    let raw: Uint8Array<ArrayBuffer> | undefined
    try {
      if (info.vault && !replacing) {
        raw = await openVault(input, info.vault, account.id, false)
        unlocked(await importVaultRoot(raw))
        return
      }
      const id = info.vault?.id ?? randomUuid()
      raw = info.vault ? await openVault(input, info.vault, account.id, recovering) : generateVaultRoot()
      const envelope = await newVaultKeys(newPassword, id, account.id, raw)
      const revision = info.vault?.revision ?? 0
      if (revision) await api('personal/keys', { ...envelope.keys, revision }, account.csrf, 'PUT')
      else await api('personal', { ...envelope.keys, id }, account.csrf)
      created({ id, keys: envelope.keys, revision: revision + 1 })
      setPending({ key: envelope.root, code: envelope.recovery })
    } catch (failure) {
      setError(failure instanceof DOMException ? 'Vault key could not unlock this vault.' : fail(failure))
    } finally { raw?.fill(0); setBusy(false) }
  }

  return <section className="account-card">
    <header className="account-brand">
      <div className="brand-mark"><ShieldCheck size={25} aria-hidden="true" /></div>
      <HttpTestMode />
    </header>
    <h1>{pending ? 'Save your recovery key' : creating ? 'Set up your vault' : changing ? 'Change vault master password' : recovering ? 'Recover your vault' : 'Unlock your vault'}</h1>
    {pending ? <div className="account-form">
      <p className="muted">Save this recovery key in a secure place outside SecureVault. It is displayed once.</p>
      <code className="recovery-code">{pending.code}</code>
      <button className="primary" onClick={() => { unlocked(pending.key); setPending(null) }}>I saved my recovery key</button>
    </div> : <form className="account-form" onSubmit={(event) => {
      event.preventDefault()
      if (!busy) void submit(new FormData(event.currentTarget))
    }}>
      <p className="muted">Your vault master password is separate from your account password.</p>
      <label>{recovering ? 'Recovery key' : changing ? 'Current vault master password' : 'Vault master password'}
        <input name="master" required type="password" maxLength={512}
          autoComplete={creating ? 'new-password' : 'off'} />
      </label>
      {replacing && <label>New vault master password<input name="next" required type="password" maxLength={512}
        autoComplete="new-password" /></label>}
      {(creating || replacing) && <label>Confirm vault master password
        <input name="confirm" required type="password" maxLength={512} autoComplete="new-password" /></label>}
      {error && <p className="error" role="alert">{error}</p>}
      <button className="primary" disabled={busy}>{busy ? 'Working…' : creating ? 'Create vault' : changing ? 'Change vault password' : recovering ? 'Recover vault' : 'Unlock vault'}</button>
      {!creating && !changing && <button className="secondary" type="button" disabled={busy}
        onClick={() => { setRecover(!recover); setError('') }}>{recover ? 'Use vault master password' : 'Use recovery key'}</button>}
      {changing && <button type="button" className="secondary" disabled={busy} onClick={cancelChange}>Cancel</button>}
    </form>}
  </section>
}

async function copySecret(value: string, seconds: number) {
  if (!navigator.clipboard) {
    if (window.location.protocol !== 'http:') throw new Error('Clipboard access is unavailable.')
    const previousFocus = document.activeElement
    const selection = document.createElement('textarea')
    selection.value = value
    selection.readOnly = true
    selection.className = 'clipboard-selection'
    document.body.append(selection)
    let copied = false
    try {
      selection.select()
      copied = document.execCommand('copy')
    } catch {
      // The browser can block legacy clipboard writes even from a user click.
    } finally {
      selection.remove()
      if (previousFocus instanceof HTMLElement) previousFocus.focus()
    }
    if (copied) return
    window.prompt('Copy this test value manually with Ctrl+C.', value)
    throw new Error('Automatic copying is unavailable in this browser.')
  }
  await navigator.clipboard.writeText(value)
  const hash = async (text: string) => new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)))
  const written = await hash(value)
  window.setTimeout(() => {
    void (async () => {
      const permission = await navigator.permissions.query({ name: 'clipboard-read' as PermissionName })
      if (permission.state !== 'granted') return
      const current = await hash(await navigator.clipboard.readText())
      if (written.every((byte, index) => current[index] === byte)) await navigator.clipboard.writeText('')
    })().catch(() => {})
  }, seconds * 1000)
}

function Fields({ value, limits, action, notice }: {
  value: Credential; limits: Limits
  action: (name: string) => Promise<void>
  notice: (message: string) => void
}) {
  const [revealed, reveal] = useState<string[]>([])
  return <dl className="credential-fields">
    {value.fields.map((field) => {
      const visible = field.type !== 'secret' || revealed.includes(field.id)
      return <div className="credential-field" key={field.id}>
        <div><dt>{field.label}</dt><dd>{visible ? field.value : '••••••••••••'}</dd></div>
        <div className="actions">
          {field.type === 'secret' && <button className="icon-button" aria-label={visible ? 'Hide ' + field.label : 'Reveal ' + field.label}
            onClick={() => {
              if (visible) reveal((previous) => previous.filter((id) => id !== field.id))
              else {
                reveal((previous) => [...previous, field.id])
                window.setTimeout(() => reveal((previous) => previous.filter((id) => id !== field.id)), limits.reveal_seconds * 1000)
                void action('reveal').catch((error) => notice(fail(error)))
              }
            }}><Eye size={16} /></button>}
          <button className="icon-button" aria-label={'Copy ' + field.label} onClick={() => {
            void copySecret(field.value, limits.clipboard_seconds).then(async () => {
              notice('Value copied.')
              await action('copy')
            }).catch((error) => notice(fail(error)))
          }}><Copy size={16} /></button>
        </div>
      </div>
    })}
  </dl>
}

function Workspace({ root, vault, account, limits, lock, logout, settings, master, shared, switchVaults }: {
  root: VaultRoot; vault: { id: string }; account: Account; limits: Limits
  lock: () => void; logout: () => void; settings: () => void; master: () => void
  shared?: SharedVault; switchVaults: () => void
}) {
  const [items, setItems] = useState<VaultRecord[]>([])
  const workspaceTabs = shared ? [shared.name, 'Recycle bin'] : [
    'Dashboard', 'My vault', 'Favorites', 'Recently used', 'Expiring secrets', 'Password health',
    'Password generator', 'Recycle bin', 'CSV import',
  ]
  const adminTabs = account.role === 'ADMIN' ? ['Users', 'Teams', 'Environments', 'Categories', 'Audit logs', 'Backup & restore', 'Application settings']
    : account.role === 'TEAM_LEAD' ? ['Teams', 'Audit logs'] : ['Audit logs']
  const [params, setParams] = useSearchParams()
  const requested = params.get('view') ?? ''
  const defaultTab = shared ? 'My vault' : 'Dashboard'
  const permitted = shared ? ['My vault', 'Recycle bin'] : [...workspaceTabs, ...adminTabs, 'Settings', 'My profile']
  const tab = permitted.includes(requested) ? requested : defaultTab
  const setTab = useCallback((next: string) => setParams({ view: next }), [setParams])
  const [selected, setSelected] = useState<string>()
  const [draft, setDraft] = useState<{ value: Credential; record?: VaultRecord }>()
  const [history, setHistory] = useState<VaultRecord[] | null>(null)
  const [version, setVersion] = useState<VaultRecord | null>(null)
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState({ category: '', environment: '', folder: '' })
  const [sort, setSort] = useState('name')
  const [message, setMessage] = useState('')
  const [collapsed, setCollapsed] = useState(false)
  const listSearch = useRef<HTMLInputElement>(null)
  const [focusSearch, setFocusSearch] = useState(false)
  const [loading, setLoading] = useState(true)
  const [refresh, setRefresh] = useState(0)
  useEffect(() => {
    if (!focusSearch || tab !== "My vault" || !listSearch.current) return
    listSearch.current.focus()
    setFocusSearch(false)
  }, [focusSearch, tab])
  useEffect(() => {
    function shortcut(event: KeyboardEvent) {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        if (draft && !window.confirm('Discard unsaved changes?')) return
        setDraft(undefined)
        setTab('My vault')
        setFocusSearch(true)
      }
    }
    window.addEventListener('keydown', shortcut)
    return () => window.removeEventListener('keydown', shortcut)
  }, [draft, setTab])
  const removed = tab === 'Recycle bin'
  const path = shared ? 'shared/vaults/' + shared.id + '/records' : 'personal/records'
  const epoch = shared?.epoch
  const epochQuery = epoch ? '&epoch=' + epoch : ''
  const allow = (permission: number) => !shared || (!shared.rotating && Boolean(shared.permissions & permission))
  const [catalog, setCatalog] = useState<{ category: CatalogEntry[]; environment: CatalogEntry[] }>(
    { category: [], environment: [] },
  )
  useEffect(() => {
    let active = true
    void Promise.all([api<CatalogEntry[]>('catalog/categories'), api<CatalogEntry[]>('catalog/environments')])
      .then(([category, environment]) => { if (active) setCatalog({ category, environment }) })
      .catch((error) => { if (active) setMessage(fail(error)) })
    return () => { active = false }
  }, [])

  function entryName(key: 'category' | 'environment' | 'folder', id: string) {
    if (key === 'folder') return id
    return catalog[key].find((entry) => entry.id === id)?.name ?? id
  }

  useEffect(() => {
    let active = true
    let cursor: string | null = null
    setLoading(true)
    setItems([])
    void (async () => {
      do {
        const query: string = path + '?deleted=' + removed + '&limit=500' + (cursor ? '&cursor=' + cursor : '')
        const page: { items: WireRecord[]; cursor: string | null; epoch?: number } = await api(query)
        if (!active) return
        if (epoch && page.epoch !== epoch) throw new Error('The shared vault key has changed. Reopen the vault.')
        const records = await Promise.all(page.items.map((item) => decrypt(root, vault.id, item, epoch)))
        if (!active) return
        setItems((previous) => [...previous, ...records])
        cursor = page.cursor
      } while (cursor)
    })().catch((error) => { if (active) setMessage(fail(error)) })
      .finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [root, vault.id, refresh, removed, path, epoch])

  const current = items.find((item) => item.id === selected)
  const filtered = items.filter(({ value, last_used }) => {
    const eligible = tab === 'Favorites' ? value.favorite : tab === 'Recently used' ? last_used !== null : true
    return eligible && [value.name, value.tags, entryName('category', value.category), entryName('environment', value.environment), value.folder].join(' ')
      .toLowerCase().includes(search.toLowerCase()) &&
      (Object.keys(filter) as Array<keyof typeof filter>).every((key) => !filter[key] || filter[key] === value[key])
  }).sort((a, b) => tab === 'Recently used' ? (b.last_used ?? 0) - (a.last_used ?? 0) :
    sort === 'modified' ? b.modified_at - a.modified_at : a.value.name.localeCompare(b.value.name))

  async function save(value: Credential, previous?: VaultRecord, importing = false) {
    const id = previous?.id ?? randomUuid()
    const version = (previous?.version ?? 0) + 1
    const plain = new TextEncoder().encode(JSON.stringify(value))
    try {
      const payload = await sealRecord(root, { vaultId: vault.id, recordId: id, version, epoch }, plain)
      const wire = await api<WireRecord>(path + '/' + id, { version, payload, ...(epoch ? { epoch } : {}) }, account.csrf, 'PUT')
      setItems((all) => [...all.filter((item) => item.id !== id), { ...wire, value }])
      if (importing) return
      setDraft(undefined)
      setHistory(null)
      setVersion(null)
      setSelected(id)
      setMessage('Credential saved.')
    } finally { plain.fill(0) }
  }
  async function action(item: VaultRecord, action: string) {
    await api(path + '/' + item.id + '/' + action + '?version=' + item.version + epochQuery, {}, account.csrf)
    if (action === 'copy' || action === 'reveal') {
      setItems((all) => all.map((record) => record.id === item.id ? { ...record, last_used: Date.now() / 1000 } : record))
    } else {
      setSelected(undefined)
      setRefresh((value) => value + 1)
      setMessage(action === 'restore' ? 'Credential restored.' : 'Credential removed.')
    }
  }
  function choose(id: string) { setSelected(id); setDraft(undefined); setHistory(null); setVersion(null) }

  function open(id: string) { choose(id); setTab('My vault') }
  function switchTab(next: string) {
    if (draft && !window.confirm('Discard unsaved changes?')) return
    choose(''); setTab(next); setSearch('')
  }
  async function exportEncrypted() {
    const current = await api<VaultInfo>('personal')
    if (!current.vault) throw new Error('Vault not found.')
    const records: WireRecord[] = []
    for (const deleted of [false, true]) {
      let cursor: string | null = null
      do {
        const suffix: string = '?limit=500&deleted=' + deleted + (cursor ? '&cursor=' + cursor : '')
        const page: { items: WireRecord[]; cursor: string | null } = await api('personal/records' + suffix)
        records.push(...page.items)
        cursor = page.cursor
      } while (cursor)
    }
    const file = new Blob([JSON.stringify({ format: 'pinaki-encrypted-vault', version: 1,
      vault: current.vault, owner: account.id, records })], { type: 'application/json' })
    const url = URL.createObjectURL(file)
    const link = document.createElement('a')
    link.href = url
    link.download = 'pinaki-vault-encrypted.json'
    link.click()
    window.setTimeout(() => URL.revokeObjectURL(url), 1000)
  }
  const nearExpiry = items.filter((item) => item.value.expiry_date && daysRemaining(item.value.expiry_date) <= 7).length

  return <div className={'workspace' + (collapsed ? ' collapsed' : '')}>
    <aside className="vault-nav">
      <div className="vault-brand"><ShieldCheck size={26} /> <div>Pinaki SecureVault<small>Team Password Manager</small></div></div>
      <nav aria-label="Workspace">
        {workspaceTabs.map((item) => {
          const Icon = navIcons[item as keyof typeof navIcons] ?? FolderLock
          return <button key={item} title={item} className={(shared && item === shared.name ? tab === 'My vault' : tab === item) ? 'active' : ''} type="button" onClick={() => {
            if (draft && !window.confirm('Discard unsaved changes?')) return
            choose(''); setTab(item === shared?.name ? 'My vault' : item); setSearch('')
          }}><Icon size={16} aria-hidden="true" />{item}</button>})}
        <button onClick={() => {
          if (!draft || window.confirm('Discard unsaved changes?')) switchVaults()
        }} title="Shared vaults"><FolderLock size={16} aria-hidden="true" />Shared vaults</button>
      </nav>
      {!shared && <nav aria-label="Administration">
        {adminTabs.map((item) => {
          const Icon = navIcons[item as keyof typeof navIcons] ?? Settings
          return <button key={item} title={item} className={tab === item ? 'active' : ''}
            onClick={() => switchTab(item)}><Icon size={16} aria-hidden="true" />{item}</button>
        })}
      </nav>}
      <div className="nav-bottom">
        {!shared && <><button title="My profile" onClick={() => switchTab('My profile')}><User size={16} aria-hidden="true" />My profile</button>
          <button title="Settings" onClick={() => switchTab('Settings')}><Settings size={16} aria-hidden="true" />Settings</button></>}<button onClick={logout}><LogOut size={16} /> Sign out</button>
      </div>
    </aside>
    <main className="workspace-main">
      <header className="vault-header">
        <h1>{shared && tab === 'My vault' ? shared.name : tab}</h1>
        <div className="actions">
          <HttpTestMode />
          <button type="button" aria-label="Search vault (Ctrl+K)" className="secondary" onClick={() => {
            switchTab('My vault'); setFocusSearch(true)
          }}>Search <kbd>Ctrl K</kbd></button>
          {!shared && <button className="secondary" aria-label={nearExpiry + ' recent expiry alerts'}
            title="Expiry alerts" onClick={() => switchTab('Expiring secrets')}><Bell size={16} /> {nearExpiry || ''}</button>}
          <button className="icon-button" aria-label="Switch theme" onClick={() => {
            const current = document.documentElement.dataset.theme
            const next = current === 'dark' || (!current && matchMedia('(prefers-color-scheme: dark)').matches)
              ? 'light' : 'dark'
            document.documentElement.dataset.theme = next; localStorage.setItem('securevault-theme', next)
          }}><SunMoon size={16} /></button>
          <button className="icon-button" aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            onClick={() => setCollapsed(!collapsed)}><PanelLeft size={16} /></button>
          <Button variant="outline" onClick={lock}><LockKeyhole size={16} /> Lock vault</Button>
          {!shared && <details className="account-menu">
            <summary aria-label="Account menu"><User size={16} /></summary>
            <div className="vault-panel account-menu-panel">
              <strong>{account.full_name}</strong>
              <button className="secondary" onClick={() => switchTab('My profile')}>My profile</button>
              <button className="secondary" onClick={logout}>Sign out</button>
            </div>
          </details>}
        </div>
      </header>
      {shared?.rotating && <p className="workspace-message">Key rotation pending. Editing is paused.</p>}
      {message && <p className="workspace-message" role="status">{message}</p>}
      {tab === 'Dashboard' ? <Dashboard records={items} open={open} navigate={switchTab} shared={switchVaults}
        add={() => { setTab('My vault'); setDraft({ value: blank() }) }} loading={loading} />
      : tab === 'Expiring secrets' ? <Expiry records={items} open={open} />
      : tab === 'Password health' ? <PasswordHealth records={items} open={open} />
      : tab === 'CSV import' ? <CsvImport items={items} limits={limits} importOne={(value) => save(value, undefined, true)}
        exportEncrypted={exportEncrypted} />
      : tab === 'Users' ? <UsersScreen account={account} />
      : tab === 'Teams' ? <TeamsScreen account={account} />
      : tab === 'Environments' || tab === 'Categories' ? <CatalogScreen key={tab} account={account}
        kind={tab === 'Environments' ? 'environments' : 'categories'} />
      : tab === 'Audit logs' ? <AuditScreen />
      : tab === 'Backup & restore' ? <Backups csrf={account.csrf} />
      : ['Settings', 'My profile', 'Application settings'].includes(tab) ? <SettingsScreen key={tab}
        account={account} password={settings} master={master} profileOnly={tab === 'My profile'} />
      : tab === 'Password generator' ? <Generator copy={(value) => copySecret(value, limits.clipboard_seconds)} /> :
      <div className="vault-layout">
        <section className="vault-panel vault-list">
          <div className="actions list-head"><strong>Credentials</strong>
            {!removed && allow(2) && <button className="primary" onClick={() => { if (!draft || window.confirm('Discard unsaved changes?')) setDraft({ value: blank() }) }}>
              <Plus size={16} /> Add credential</button>}
          </div>
          <input ref={listSearch} type="search" aria-label="Search credentials" placeholder="Search credentials" value={search}
            onChange={(event) => setSearch(event.target.value)} />
          <div className="filters">
            {(Object.keys(filter) as Array<keyof typeof filter>).map((key) => (
              <select key={key} value={filter[key]} aria-label={'Filter by ' + key}
                onChange={(event) => setFilter({ ...filter, [key]: event.target.value })}>
                <option value="">{key === 'category' ? 'All categories' : 'All ' + key + 's'}</option>
                {[...new Set(items.map((item) => item.value[key]).filter(Boolean))].sort().map((option) =>
                  <option key={option} value={option}>{entryName(key, option)}</option>)}
              </select>
            ))}
            <select aria-label="Sort credentials" value={sort} onChange={(event) => setSort(event.target.value)}>
              <option value="name">Name</option><option value="modified">Last modified</option>
            </select>
          </div>
          {loading ? <p role="status">Loading credentials…</p> : filtered.length === 0 && <p className="muted">
            {search ? 'No matching credentials.' : removed ? 'The recycle bin is empty.' : 'No credentials to display.'}</p>}
          {filtered.map((item) => (
            <button className={'record-button ' + (selected === item.id ? 'current' : '')}
              key={item.id} onClick={() => {
                if (!draft || window.confirm('Discard unsaved changes?')) choose(item.id)
              }}>
              <KeyRound size={17} /><span><strong>{item.value.name}</strong>
                <small>{entryName('environment', item.value.environment) || entryName('category', item.value.category) || date(item.modified_at)}</small>
              </span>{item.value.favorite && <Star size={15} aria-label="Favorite" />}
            </button>
          ))}
        </section>
        {draft ? <Editor key={draft.record?.id ?? 'new'} value={draft.value} limits={limits} catalog={catalog}
          save={(value) => save(value, draft.record)} close={() => setDraft(undefined)} />
          : !current ? <section className="vault-panel empty-detail"><KeyRound size={26} />
            <h2>Select a credential</h2><p className="muted">Credential details will appear here.</p>
          </section> : <section className="vault-panel detail">
            <div className="list-head actions"><h2>{current.value.name}</h2>
              {!removed && allow(4) && <button className="secondary" onClick={() => setDraft({ value: current.value, record: current })}>Edit</button>}
            </div>
            <p className="muted">{[entryName('category', current.value.category), entryName('environment', current.value.environment), current.value.folder].filter(Boolean).join(' · ')}</p>
            {removed ? allow(8) && <div className="actions">
              <button className="primary" onClick={() => void action(current, 'restore').catch((error) => setMessage(fail(error)))}>Restore</button>
              <button className="secondary" onClick={() => {
                if (window.confirm('Permanently delete this credential?')) void action(current, 'purge').catch((error) => setMessage(fail(error)))
              }}>Permanently delete</button>
            </div> : <>
              <div className="actions">
                {!shared && <button className="secondary" onClick={() => void save({ ...current.value, favorite: !current.value.favorite }, current)
                  .catch((error) => setMessage(fail(error)))}><Star size={16} /> {current.value.favorite ? 'Unfavorite' : 'Favorite'}</button>}
                {allow(2) && <button className="secondary" onClick={() => setDraft({ value: { ...current.value, name: current.value.name + ' copy' } })}>Duplicate</button>}
                {allow(8) && <button className="secondary" onClick={() => {
                  if (window.confirm('Move this credential to the recycle bin?')) void action(current, 'delete').catch((error) => setMessage(fail(error)))
                }}>Delete</button>}
                <button className="secondary" onClick={() => {
                  if (history) { setHistory(null); setVersion(null); return }
                  void api<Array<WireRecord>>(path + '/' + current.id + '/history')
                    .then((rows) => Promise.all(rows.map((row) => decrypt(root, vault.id, { ...row, id: current.id }, epoch))))
                    .then(setHistory).catch((error) => setMessage(fail(error)))
                }}>{history ? 'Close history' : 'History'}</button>
              </div>
              {history && <div className="history">
                <h3>History</h3>
                {history.length === 0 && <p className="muted">No previous versions.</p>}
                {history.map((item) => <button className="secondary" key={item.version}
                  onClick={() => setVersion(item)}>Version {item.version} · {date(item.modified_at)}</button>)}
                {version && allow(4) && <button className="primary" onClick={() => {
                  if (window.confirm('Restore this version?')) void save(version.value, current).catch((error) => setMessage(fail(error)))
                }}>Restore selected version</button>}
              </div>}
              <Fields key={current.id + ':' + (version?.version ?? current.version)} value={version?.value ?? current.value}
                limits={limits} action={(name) => action(current, name)} notice={setMessage} />
              {(version ?? current).value.notes && <p className="notes">{(version ?? current).value.notes}</p>}
              {(version ?? current).value.tags && <p className="muted">Tags · {(version ?? current).value.tags}</p>}
              {(version ?? current).value.expiry_date && <p className="muted">Expiry · {(version ?? current).value.expiry_date}</p>}
            </>}
            <small className="muted">Created {date(current.created_at)} · Modified {date(current.modified_at)}</small>
          </section>}
      </div>}
    </main>
  </div>
}

export function PersonalWorkspace({ account, logout, settings }: { account: Account; logout: () => void; settings: () => void }) {
  const [info, setInfo] = useState<VaultInfo | null>(null)
  const [changing, setChanging] = useState(false)
  const [sharedMenu, setSharedMenu] = useState(false)
  const [sharedSelection, setSharedSelection] = useState<{ vault: SharedVault; root: VaultRoot } | null>(null)
  function lock() { setSharedSelection(null); setSharedMenu(false); setRoot(null) }
  const [root, setRoot] = useState<VaultRoot | null>(null)
  const [error, setError] = useState('')
  useEffect(() => {
    let gone = false
    api<VaultInfo>('personal').then((data) => { if (!gone) setInfo(data) })
      .catch((error) => { if (!gone) setError(fail(error)) })
    return () => { gone = true }
  }, [])
  useEffect(() => {
    if (!root || !info) return
    let timeout = 0
    const refresh = () => {
      window.clearTimeout(timeout)
      timeout = window.setTimeout(lock, info.limits.auto_lock_minutes * 60000)
    }
    const activity = ['pointerdown', 'keydown', 'wheel']
    for (const event of activity) window.addEventListener(event, refresh, { passive: true })
    refresh()
    return () => {
      window.clearTimeout(timeout)
      for (const event of activity) window.removeEventListener(event, refresh)
    }
  }, [root, info])
  if (info?.vault && root) {
    if (sharedMenu && !sharedSelection) return <SharedVaults account={account} root={root}
      personalId={info.vault.id} back={() => setSharedMenu(false)} open={setSharedSelection} logout={logout} />
    return <Workspace key={sharedSelection?.vault.id ?? info.vault.id}
      root={sharedSelection?.root ?? root} vault={sharedSelection?.vault ?? info.vault}
      shared={sharedSelection?.vault} limits={info.limits} account={account}
      lock={lock} logout={logout} settings={settings}
      switchVaults={() => { setSharedSelection(null); setSharedMenu(true) }}
      master={() => { lock(); setChanging(true) }} />
  }
  return <main className="account-page">
    {info ? <VaultGate account={account} info={info} unlocked={(key) => { setChanging(false); setRoot(key) }}
      created={(vault) => setInfo({ ...info, vault })} changing={changing}
      cancelChange={() => setChanging(false)} />
      : <section className="account-card"><p role="status">{error || 'Loading vault…'}</p></section>}
    <footer><button className="secondary" onClick={logout}>Sign out</button></footer>
  </main>
}

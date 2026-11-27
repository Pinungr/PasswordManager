import { useEffect, useState } from 'react'
import { Activity, ArrowRight, Clock3, KeyRound, Shield, Star } from 'lucide-react'
import { api } from '../services/api'
import type { VaultRecord } from './data'

type Audit = { id: number; action: string; timestamp: number; result: string }
type Summary = { shared_credentials: number; admin: { users: number; teams: number; capacity: number } | null }
export function daysRemaining(expiry: string) {
  const local = new Date()
  const today = Date.UTC(local.getFullYear(), local.getMonth(), local.getDate())
  return (Date.parse(expiry) - today) / 86400000
}
const expiryLabel = (record: VaultRecord) => {
  const days = daysRemaining(record.value.expiry_date)
  if (days < 0) return Math.abs(days) + ' days overdue'
  return days === 0 ? 'Today' : days + ' days remaining'
}

function health(records: VaultRecord[]) {
  const passwords = new Map<string, Set<string>>()
  const weak = new Set<string>()
  for (const item of records) {
    for (const field of item.value.fields) {
      if (field.type !== 'secret' || !/\b(password|passphrase)\b/i.test(field.label)) continue
      const occurrences = passwords.get(field.value) ?? new Set()
      occurrences.add(item.id)
      passwords.set(field.value, occurrences)
      if (field.value.length < 12 || /^(.)\1+$/.test(field.value) ||
        /^(password|qwerty|letmein|123456)/i.test(field.value)) weak.add(item.id)
    }
  }
  const reused = new Set([...passwords.values()].filter((ids) => ids.size > 1).flatMap((ids) => [...ids]))
  return {
    weak: records.filter((item) => weak.has(item.id)),
    reused: records.filter((item) => reused.has(item.id)),
    expired: records.filter((item) => item.value.expiry_date && daysRemaining(item.value.expiry_date) < 0),
    soon: records.filter((item) => item.value.expiry_date && daysRemaining(item.value.expiry_date) >= 0
      && daysRemaining(item.value.expiry_date) <= 30),
  }
}

function RecordRows({ records, open, showExpiry = false }: {
  records: VaultRecord[]; open: (id: string) => void; showExpiry?: boolean
}) {
  if (!records.length) return <p className="muted">No credentials to display.</p>
  return <div className="insight-records">
    {records.map((record) => <button className="insight-record" key={record.id} onClick={() => open(record.id)}>
      <KeyRound size={15} /><span><strong>{record.value.name}</strong>
        {showExpiry && <small>{record.value.expiry_date} · {expiryLabel(record)}</small>}
      </span><ArrowRight size={15} aria-hidden="true" />
    </button>)}
  </div>
}

export function Dashboard({ records, open, navigate, add, shared, loading }: {
  records: VaultRecord[]; open: (id: string) => void; navigate: (name: string) => void
  add: () => void; shared: () => void; loading: boolean
}) {
  const [summary, setSummary] = useState<Summary>()
  const [activity, setActivity] = useState<Audit[]>([])
  const [error, setError] = useState('')
  const report = health(records)
  useEffect(() => {
    let active = true
    void Promise.all([api<Summary>('summary'), api<{ items: Audit[] }>('audit')]).then(([counts, events]) => {
      if (active) { setSummary(counts); setActivity(events.items.slice(0, 6)) }
    }).catch(() => { if (active) setError('Unable to load activity and shared counts.') })
    return () => { active = false }
  }, [])
  const metrics = [
    { label: 'My credentials', count: loading ? '…' : records.length, icon: KeyRound, click: () => navigate('My vault') },
    { label: 'Shared credentials', count: summary?.shared_credentials ?? '…', icon: Shield, click: shared },
    { label: 'Expiring credentials', count: loading ? '…' : report.soon.length, icon: Clock3, click: () => navigate('Expiring secrets') },
    { label: 'Favorites', count: loading ? '…' : records.filter((item) => item.value.favorite).length, icon: Star, click: () => navigate('Favorites') },
  ]
  return <div className="admin-stack">
    {error && <p className="error" role="alert">{error}</p>}
    <div className="metrics">
      {metrics.map(({ label, count, icon: Icon, click }) => <button className="vault-panel metric" key={label} onClick={click}>
        <span><Icon size={16} aria-hidden="true" /> {label}</span><strong>{count}</strong>
      </button>)}
    </div>
    <div className="dashboard-grid">
      <section className="vault-panel editor"><h2>Recently used credentials</h2>
        <RecordRows records={records.filter((item) => item.last_used !== null).sort((a, b) =>
          (b.last_used ?? 0) - (a.last_used ?? 0)).slice(0, 5)} open={open} /></section>
      <section className="vault-panel editor"><h2>Credential health</h2>
        <p>{report.weak.length} weak · {report.reused.length} reused · {report.expired.length} expired</p>
        <button className="secondary fit" onClick={() => navigate('Password health')}>Open password health</button>
        <h2>Quick actions</h2><div className="actions">
          <button className="primary" onClick={add}>Add credential</button>
          <button className="secondary" onClick={() => navigate('My vault')}>Open my vault</button>
          <button className="secondary" onClick={shared}>Open shared vaults</button>
          <button className="secondary" onClick={() => navigate('Password generator')}>Generate password</button>
        </div>
      </section>
      <section className="vault-panel editor"><h2><Activity size={17} aria-hidden="true" /> Recent authorized activity</h2>
        {activity.length === 0 ? <p className="muted">No recent activity.</p> : <ul className="admin-stack">
          {activity.map((event) => <li key={event.id} className="list-head"><span>{event.action.replaceAll('.', ' ')}</span>
            <small className="muted">{new Date(event.timestamp * 1000).toLocaleString()}</small></li>)}
        </ul>}
      </section>
      {summary?.admin && <section className="vault-panel editor"><h2>Installation summary</h2>
        <p>{summary.admin.users} registered users · {summary.admin.capacity - summary.admin.users} available slots</p>
        <p>{summary.admin.teams} teams</p></section>}
    </div>
  </div>
}

export function Expiry({ records, open }: { records: VaultRecord[]; open: (id: string) => void }) {
  const [windowDays, setWindowDays] = useState(-1)
  const results = records.filter(({ value }) => {
    if (!value.expiry_date) return false
    const days = daysRemaining(value.expiry_date)
    return windowDays < 0 ? days < 0 : days >= 0 && days <= windowDays
  }).sort((a, b) => a.value.expiry_date.localeCompare(b.value.expiry_date))
  return <section className="vault-panel editor">
    <div className="actions" aria-label="Expiry windows">
      {[[-1, 'Expired'], [7, 'Within 7 days'], [30, 'Within 30 days'], [Infinity, 'All upcoming']].map(([days, name]) =>
        <button key={name} className={days === windowDays ? 'primary' : 'secondary'}
          aria-pressed={days === windowDays} onClick={() => setWindowDays(Number(days))}>{name}</button>)}
    </div>
    <RecordRows records={results} open={open} showExpiry />
  </section>
}

export function PasswordHealth({ records, open }: { records: VaultRecord[]; open: (id: string) => void }) {
  const report = health(records)
  return <div className="dashboard-grid">
    {([['Weak passwords', report.weak], ['Reused passwords', report.reused], ['Expired credentials', report.expired],
      ['Approaching expiry', report.soon]] as const).map(([name, records], index) =>
      <section className="vault-panel editor" key={name}><h2>{name} · {records.length}</h2>
        <RecordRows records={records} open={open} showExpiry={index >= 2} />
      </section>)}
  </div>
}

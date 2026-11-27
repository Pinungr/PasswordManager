import { ShieldCheck } from 'lucide-react'
import { useEffect, useState } from 'react'
import { HttpTestMode } from '../components/ui/HttpTestMode'
import { randomUuid } from '../crypto/browser'
import {
  fingerprints, generateIdentity, getPublicIdentity, openGrant, privateIdentity, sealGrant,
} from '../crypto/shared'
import type { PrivateIdentity, PublicIdentity } from '../crypto/shared'
import { generateVaultRoot, importVaultRoot, openRecord, sealRecord } from '../crypto/record'
import type { Envelope, VaultRoot } from '../crypto/record'
import { api } from '../services/api'
import type { WireRecord } from './data'

export type SharedVault = {
  id: string; team_id: string; team_name: string; name: string; description: string
  epoch: number; rotating: boolean; membership_version: number; permissions: number; grant: string; grantor: string
}

type Account = { id: string; full_name: string; csrf: string; role: string }
type Team = { id: string; name: string; active: boolean; lead_id: string | null }
type Member = { id: string; username: string; full_name: string; public_keys: PublicIdentity | null }
type Access = { user_id: string; username: string; full_name: string; permissions: number }
type Selected = { vault: SharedVault; root: VaultRoot }
type Plan = { id: string; old_epoch: number; next_epoch: number; members: string[] }
type RotationItem = Pick<WireRecord, 'id' | 'crypto_version' | 'payload'>

const keyDomain = 'shared-identity' as const
const options = [['View', 1], ['Create', 2], ['Edit', 4], ['Delete', 8], ['Manage access', 16]] as const
const failureText = (error: unknown) => error instanceof Error ? error.message : 'Shared vault operation failed.'

export function SharedVaults({ account, root, personalId, back, open, logout }: {
  account: Account; root: VaultRoot; personalId: string; back: () => void
  open: (selection: Selected) => void; logout: () => void
}) {
  const [identity, setIdentity] = useState<PrivateIdentity | null>(null)
  const [vaults, setVaults] = useState<SharedVault[]>([])
  const [teams, setTeams] = useState<Team[]>([])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [selected, setSelected] = useState<SharedVault | null>(null)
  const [mode, setMode] = useState<'open' | 'manage'>('open')
  const [creating, setCreating] = useState(false)
  const [keyPins, setKeyPins] = useState({ agreement: '', signing: '' })
  const [agreementPins, setAgreementPins] = useState<Record<string, string>>({})
  const [grantorPin, setGrantorPin] = useState('')
  const [search, setSearch] = useState('')
  const [teamFilter, setTeamFilter] = useState('')
  const [directory, setDirectory] = useState<Member[]>([])
  const [grants, setGrants] = useState<Access[]>([])
  const [progress, setProgress] = useState('')
  const [reload, setReload] = useState(0)

  useEffect(() => {
    let active = true
    const binding = { vaultId: personalId, recordId: account.id, version: 1, purpose: keyDomain }
    void Promise.all([
      api<{ private_envelope: Envelope } | null>('shared/identity'),
      api<SharedVault[]>('shared/vaults'),
      api<Team[]>('teams'),
    ]).then(async ([profile, list, allTeams]) => {
      if (!active) return
      setVaults(list)
      setTeams(allTeams.filter((team) => team.active))
      if (!profile) return
      const bytes = await openRecord(root, binding, profile.private_envelope)
      try {
        const privateKeys = privateIdentity.parse(JSON.parse(new TextDecoder().decode(bytes)))
        const pins = await fingerprints(getPublicIdentity(privateKeys))
        if (active) { setIdentity(privateKeys); setKeyPins(pins) }
      } finally { bytes.fill(0) }
    }).catch((error) => { if (active) setError(failureText(error)) })
      .finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [account.id, personalId, root, reload])

  async function task(work: () => Promise<void>) {
    if (busy) return
    setBusy(true)
    setError('')
    try { await work() } catch (error) { setError(failureText(error)) }
    finally { setBusy(false); setProgress('') }
  }

  async function initialize() {
    const keys = await generateIdentity()
    const publicIdentity = getPublicIdentity(keys)
    const bytes = new TextEncoder().encode(JSON.stringify(keys))
    try {
      const envelope = await sealRecord(root, {
        vaultId: personalId, recordId: account.id, version: 1, purpose: keyDomain,
      }, bytes)
      await api('shared/identity', { ...publicIdentity, private_envelope: envelope }, account.csrf)
      setKeyPins(await fingerprints(publicIdentity))
      setIdentity(keys)
    } finally { bytes.fill(0) }
  }

  async function makeGrant(raw: Uint8Array<ArrayBuffer>, vault: string, epoch: number, recipient: string,
                           key: PublicIdentity['agreement'], verifiedPin: string) {
    if (!identity) throw new Error('Set up your shared vault identity first.')
    return sealGrant(raw, { vault, epoch, sender: account.id, recipient, recipientKey: verifiedPin },
      identity.signing, key)
  }

  async function create(form: FormData) {
    if (!identity) return
    const id = randomUuid()
    const team = String(form.get('team'))
    const raw = generateVaultRoot()
    try {
      const grant = await makeGrant(raw, id, 1, account.id, getPublicIdentity(identity).agreement, keyPins.agreement)
      await api('shared/teams/' + team + '/vaults', {
        id, name: String(form.get('name')), description: String(form.get('description')), grant,
      }, account.csrf)
      setCreating(false)
      setReload((value) => value + 1)
    } finally { raw.fill(0) }
  }

  async function unlock(vault: SharedVault) {
    if (!identity) throw new Error('Set up your shared vault identity first.')
    const path = 'shared/vaults/' + vault.id
    const grantor = await api<{ id: string; signing: PublicIdentity['signing'] }>(path + '/grantor')
    return openGrant(vault.grant, {
      vault: vault.id, epoch: vault.epoch, sender: grantor.id, recipient: account.id, recipientKey: keyPins.agreement,
    }, grantor.id === account.id ? keyPins.signing : grantorPin.trim(), grantor.signing, identity.agreement)
  }

  async function select(vault: SharedVault, nextMode: 'open' | 'manage') {
    setGrantorPin('')
    setAgreementPins({})
    setMode(nextMode)
    setSelected(vault)
    setDirectory([])
    setGrants([])
    if (nextMode === 'manage') {
      const [members, access] = await Promise.all([
        api<Member[]>('shared/teams/' + vault.team_id + '/directory'),
        api<Access[]>('shared/vaults/' + vault.id + '/access'),
      ])
      setDirectory(members)
      setGrants(access)
    }
  }

  async function addGrant(vault: SharedVault, form: FormData) {
    const member = directory.find((entry) => entry.id === form.get('member'))
    if (!member?.public_keys) throw new Error('Choose a member with a shared identity.')
    const pin = String(form.get('fingerprint')).trim()
    const permissions = 1 | form.getAll('permission').reduce<number>((mask, part) => mask | Number(part), 0)
    const raw = await unlock(vault)
    try {
      const grant = await makeGrant(raw, vault.id, vault.epoch, member.id, member.public_keys.agreement, pin)
      await api('shared/vaults/' + vault.id + '/access/' + member.id, {
        grant, permissions, epoch: vault.epoch, membership_version: vault.membership_version,
      }, account.csrf, 'PUT')
      setSelected(null)
      setReload((value) => value + 1)
    } finally { raw.fill(0) }
  }

  async function rotate(vault: SharedVault) {
    if (!identity) return
    const raw = await unlock(vault)
    const replacement = generateVaultRoot()
    try {
      const [previous, next] = await Promise.all([importVaultRoot(raw), importVaultRoot(replacement)])
      const path = 'shared/vaults/' + vault.id + '/rotation'
      for (const access of grants) {
        if (access.user_id === account.id) continue
        const member = directory.find((entry) => entry.id === access.user_id)
        if (!member?.public_keys || (await fingerprints(member.public_keys)).agreement !== agreementPins[member.id]?.trim()) {
          throw new Error('Verify each remaining member’s agreement fingerprint.')
        }
      }
      const rotation = await api<Plan>(path, {}, account.csrf)
      const tokens: Record<string, string> = {}
      for (const id of rotation.members) {
        const member = directory.find((entry) => entry.id === id)
        const publicKey = id === account.id ? getPublicIdentity(identity) : member?.public_keys
        const pin = id === account.id ? keyPins.agreement : agreementPins[id]?.trim()
        if (!publicKey || !pin) throw new Error('Shared vault membership changed. Reload and try again.')
        tokens[id] = await makeGrant(replacement, vault.id, rotation.next_epoch, id, publicKey.agreement, pin)
      }
      const stage = path + '/' + rotation.id
      let cursor = ''
      let count = 0
      while (true) {
        const batch = await api<{ items: RotationItem[]; more: boolean }>(stage + '/records' + cursor)
        for (const item of batch.items) {
          const context = { vaultId: vault.id, recordId: item.id, version: item.crypto_version }
          const bytes = await openRecord(previous, { ...context, epoch: rotation.old_epoch }, item.payload)
          try {
            const payload = await sealRecord(next, { ...context, epoch: rotation.next_epoch }, bytes)
            await api(stage + '/records', { records: [{ ...item, payload }] }, account.csrf, 'PUT')
          } finally { bytes.fill(0) }
          setProgress('Encrypted versions prepared · ' + ++count)
        }
        if (!batch.more) break
        const last = batch.items.at(-1)!
        cursor = '?after_id=' + last.id + '&after_version=' + last.crypto_version
      }
      await api(stage + '/finish', { grants: tokens }, account.csrf)
      setSelected(null)
      setReload((value) => value + 1)
    } finally { raw.fill(0); replacement.fill(0) }
  }

  const controlledTeams = teams.filter((team) => account.role === 'ADMIN' ||
    (account.role === 'TEAM_LEAD' && team.lead_id === account.id))
  const visibleVaults = vaults.filter((vault) => (!teamFilter || vault.team_id === teamFilter) &&
    [vault.name, vault.team_name, vault.description].join(' ').toLowerCase().includes(search.toLowerCase()))

  return <div className="workspace">
    <aside className="vault-nav">
      <div className="vault-brand"><ShieldCheck size={26} /><div>Pinaki SecureVault<small>Team Password Manager</small></div></div>
      <nav><button onClick={back} disabled={busy}>My vault</button><span className="active current-page" aria-current="page">Shared vaults</span></nav>
      <div className="nav-bottom"><button onClick={logout}>Sign out</button></div>
    </aside>
    <main className="workspace-main">
      <header className="vault-header"><h1>Shared vaults</h1>
        <div className="actions">
          <HttpTestMode />
          {identity && controlledTeams.length > 0 && <button className="primary" disabled={busy}
            onClick={() => { setCreating(!creating); setSelected(null) }}>Create shared vault</button>}
        </div>
      </header>
      {error && <p role="alert" className="workspace-message error">{error}</p>}
      {loading ? <p role="status">Loading shared vaults…</p> : !identity ? <section className="vault-panel editor">
        <h2>Set up your sharing identity</h2>
        <p className="muted">Create signing and agreement keys before receiving shared vault access.</p>
        <button className="primary fit" disabled={busy} onClick={() => void task(initialize)}>Set up identity</button>
      </section> : <>
        <details className="vault-panel"><summary>My identity fingerprints</summary>
          <p className="muted">Verify these fingerprints through an independent trusted channel.</p>
          <dl className="credential-fields">
            <div><dt>Agreement</dt><dd><code>{keyPins.agreement}</code></dd></div>
            <div><dt>Signing</dt><dd><code>{keyPins.signing}</code></dd></div>
          </dl>
        </details>
        {creating && <form className="vault-panel editor shared-form" onSubmit={(event) => {
          event.preventDefault()
          const form = new FormData(event.currentTarget)
          void task(() => create(form))
        }}>
          <label>Vault name<input name="name" required maxLength={200} /></label>
          <label>Team<select name="team" required>{controlledTeams.map((team) => <option key={team.id} value={team.id}>{team.name}</option>)}</select></label>
          <label>Description<textarea name="description" maxLength={1000} /></label>
          <div className="actions"><button className="primary" disabled={busy}>Create vault</button>
            <button className="secondary" type="button" disabled={busy} onClick={() => setCreating(false)}>Cancel</button></div>
        </form>}
        <div className="shared-filters">
          <input type="search" aria-label="Search shared vaults" placeholder="Search shared vaults" value={search}
            onChange={(event) => setSearch(event.target.value)} />
          <select aria-label="Team filter" value={teamFilter} onChange={(event) => setTeamFilter(event.target.value)}>
            <option value="">All teams</option>
            {teams.map((team) => <option key={team.id} value={team.id}>{team.name}</option>)}
          </select>
        </div>
        {visibleVaults.length === 0 && <p className="muted">No shared vaults available.</p>}
        <div className="shared-grid">
          {visibleVaults.map((vault) => <section className="vault-panel editor" key={vault.id}>
            <h2>{vault.name}</h2><p className="muted">{vault.team_name}</p>
            {vault.description && <p>{vault.description}</p>}
            {vault.rotating && <p className="muted">Key rotation pending</p>}
            <p className="muted">{options.filter((entry) => Boolean(vault.permissions & entry[1])).map((entry) => entry[0]).join(' · ')}</p>
            <div className="actions">
              <button className="primary" disabled={busy} onClick={() => void task(() => select(vault, 'open'))}>Open vault</button>
              {Boolean(vault.permissions & 16) && <button className="secondary" disabled={busy}
                onClick={() => void task(() => select(vault, 'manage'))}>Manage access</button>}
            </div>
          </section>)}
        </div>
        {selected && <section className="vault-panel editor shared-form">
          <h2>{mode === 'open' ? 'Open' : 'Manage'} {selected.name}</h2>
          {selected.grantor !== account.id && <label>Verified grantor signing fingerprint
            <input autoComplete="off" value={grantorPin} onChange={(event) => setGrantorPin(event.target.value)} /></label>}
          {mode === 'open' ? <button className="primary fit" disabled={busy} onClick={() => void task(async () => {
            const bytes = await unlock(selected)
            try { open({ vault: selected, root: await importVaultRoot(bytes) }) }
            finally { bytes.fill(0) }
          })}>Unlock shared vault</button> : <>
            {grants.map((access) => <div className="list-head" key={access.user_id}>
              <span>{access.full_name} <small className="muted">{access.username}</small></span>
              {access.user_id !== account.id && <button className="secondary" disabled={busy} onClick={() => {
                if (window.confirm('Revoke access and require shared key rotation?')) void task(async () => {
                  await api('shared/vaults/' + selected.id + '/access/' + access.user_id, undefined, account.csrf, 'DELETE')
                  setSelected(null)
                  setReload((value) => value + 1)
                })
              }}>Revoke</button>}
            </div>)}
            {selected.rotating ? <>
              <h3>Rotate encryption key</h3>
              {grants.filter((access) => access.user_id !== account.id).map((access) =>
                <label key={access.user_id}>Verified agreement fingerprint for {access.username}
                  <input autoComplete="off" value={agreementPins[access.user_id] ?? ''} onChange={(event) =>
                    setAgreementPins({ ...agreementPins, [access.user_id]: event.target.value })} />
                </label>)}
              <button className="primary fit" disabled={busy} onClick={() => void task(() => rotate(selected))}>Rotate vault key</button>
              {progress && <p role="status">{progress}</p>}
            </> : <form className="editor" onSubmit={(event) => {
              event.preventDefault()
              const form = new FormData(event.currentTarget)
              void task(() => addGrant(selected, form))
            }}>
              <label>Member<select name="member" required><option value="">Choose an existing member</option>
                {directory.filter((member) => member.public_keys && member.id !== account.id).map((member) =>
                  <option key={member.id} value={member.id}>{member.username}</option>)}
              </select></label>
              <label>Independently verified agreement fingerprint<input autoComplete="off" name="fingerprint" required /></label>
              <div className="actions">{options.slice(1).map(([label, bit]) =>
                <label key={bit} className="checkbox"><input name="permission" type="checkbox" value={bit} /> {label}</label>)}</div>
              <button className="primary fit" disabled={busy}>Grant access</button>
            </form>}
          </>}
          <button className="secondary fit" disabled={busy} onClick={() => setSelected(null)}>Close</button>
        </section>}
      </>}
    </main>
  </div>
}

import { z } from 'zod'
import { randomUuid } from '../crypto/browser'
import type { Envelope } from '../crypto/record'

export const fieldType = z.enum(['text', 'secret', 'multiline', 'url'])
export type FieldType = z.infer<typeof fieldType>
export const credential = z.object({
  schema_version: z.literal(1),
  name: z.string().max(200).refine((value) => value.trim().length > 0),
  category: z.string().max(200),
  environment: z.string().max(200),
  folder: z.string().max(200),
  tags: z.string().max(2000),
  notes: z.string().max(20000),
  expiry_date: z.string().max(10),
  favorite: z.boolean(),
  fields: z.array(z.object({
    id: z.uuid(),
    label: z.string().max(200).refine((value) => value.trim().length > 0),
    type: fieldType,
    value: z.string().refine((value) => value.trim().length > 0),
  })).min(1).refine((fields) => new Set(fields.map((field) => field.id)).size === fields.length),
})

export type Credential = z.infer<typeof credential>
export type Field = Credential['fields'][number]
export type Limits = {
  max_fields: number
  max_value_bytes: number
  auto_lock_minutes: number
  reveal_seconds: number
  clipboard_seconds: number
}

export interface WireRecord {
  id: string
  version: number
  crypto_version: number
  payload: Envelope
  modified_at: number
  created_at: number
  deleted_at: number | null
  last_used: number | null
}

export type CatalogEntry = { id: string; name: string; active: boolean }

export type VaultRecord = WireRecord & { value: Credential }

export function emptyField(label = '', type: FieldType = 'secret'): Field {
  return { id: randomUuid(), label, type, value: '' }
}

export function blank(): Credential {
  return { schema_version: 1, name: '', category: '', environment: '', folder: '', notes: '',
    tags: '', expiry_date: '', favorite: false, fields: [emptyField()] }
}

export const templates: Record<string, Array<[string, FieldType]>> = {
  Generic: [['Value', 'secret']],
  'Website Login': [['URL', 'url'], ['Username', 'text'], ['Password', 'secret']],
  'Application Login': [['Application', 'text'], ['Username', 'text'], ['Password', 'secret']],
  Database: [['Host', 'text'], ['Port', 'text'], ['Database', 'text'], ['Username', 'text'], ['Password', 'secret']],
  'API Token': [['Endpoint', 'url'], ['Token', 'secret']],
  Azure: [['Tenant ID', 'text'], ['Client ID', 'text'], ['Client Secret', 'secret'], ['Subscription ID', 'text']],
  Databricks: [['Workspace URL', 'url'], ['Access Token', 'secret']],
  GitHub: [['Organization', 'text'], ['Username', 'text'], ['PAT', 'secret']],
  'Kubernetes / AKS': [['Cluster', 'text'], ['Namespace', 'text'], ['Kubeconfig', 'secret']],
  SSH: [['Host', 'text'], ['Username', 'text'], ['Private Key', 'secret'], ['Passphrase', 'secret']],
  ServiceNow: [['Instance URL', 'url'], ['Username', 'text'], ['Password', 'secret']],
  'Service Account': [['Account Name', 'text'], ['Password', 'secret']],
  'Secure Notes': [['Note', 'secret']],
  Custom: [['', 'secret']],
}

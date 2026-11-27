export class ApiError extends Error {
  constructor(readonly status: number, message: string) { super(message) }
}

export async function api<T>(path: string, data?: unknown, csrf?: string, method?: string): Promise<T> {
  const headers: Record<string, string> = {}
  if (csrf) headers['X-CSRF-Token'] = csrf
  if (data !== undefined) headers['Content-Type'] = 'application/json'
  const response = await fetch('/api/v1/' + path, {
    method: method ?? (data === undefined ? 'GET' : 'POST'), headers,
    body: data === undefined ? undefined : JSON.stringify(data),
  })
  if (response.status === 204) return undefined as T
  if (response.status === 401 && !path.startsWith('auth/')) {
    window.dispatchEvent(new Event('securevault:session-expired'))
  }
  const payload: unknown = await response.json().catch(() => undefined)
  if (!response.ok) {
    const detail = payload && typeof payload === 'object' && 'detail' in payload
      && typeof payload.detail === 'string' ? payload.detail : undefined
    throw new ApiError(response.status, detail || `Request failed (HTTP ${response.status}).`)
  }
  if (payload === undefined) throw new ApiError(response.status, 'The server returned an invalid response.')
  return payload as T
}

import type { Account } from '@/types'

export type OpenAIOAuthDiagnostic =
  | 'credentials_rejected'
  | 'refresh_token_missing'
  | 'upstream_401_cooldown'
  | 'refresh_retry_exhausted'
  | 'other_error'

type DiagnosticAccount = Pick<
  Account,
  'platform' | 'type' | 'status' | 'error_message' | 'temp_unschedulable_until' | 'temp_unschedulable_reason'
>

export function classifyOpenAIOAuthDiagnostic(account: DiagnosticAccount): OpenAIOAuthDiagnostic | null {
  if (account.platform !== 'openai' || account.type !== 'oauth') return null

  const error = (account.error_message || '').trim().toLowerCase()
  const temporaryReason = (account.temp_unschedulable_reason || '').trim().toLowerCase()
  const isTemporarilyBlocked = Boolean(
    account.temp_unschedulable_until && new Date(account.temp_unschedulable_until).getTime() > Date.now()
  )

  if (account.status === 'error' && (
    error.includes('token_invalidated') || error.includes('token_revoked') || error.startsWith('token revoked (401)')
  )) {
    return 'credentials_rejected'
  }
  if (account.status === 'error' && (error.includes('oauth 401 (no refresh_token)') || error.includes('refresh_token missing'))) {
    return 'refresh_token_missing'
  }
  if (isTemporarilyBlocked && (temporaryReason.startsWith('oauth 401:') || temporaryReason.startsWith('oauth 401 '))) {
    return 'upstream_401_cooldown'
  }
  if (isTemporarilyBlocked && temporaryReason.includes('token refresh retry exhausted')) {
    return 'refresh_retry_exhausted'
  }
  if (account.status === 'error' && error.startsWith('token refresh failed (non-retryable):') && [
    'invalid_grant',
    'invalid_refresh_token',
    'token_expired',
    'refresh_token_reused',
    'refresh_token_invalidated'
  ].some((code) => error.includes(code))) {
    return 'credentials_rejected'
  }
  if (account.status === 'error' && error) return 'other_error'

  return null
}

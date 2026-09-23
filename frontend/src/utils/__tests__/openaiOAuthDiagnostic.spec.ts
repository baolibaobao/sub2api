import { describe, expect, it } from 'vitest'
import type { Account } from '@/types'
import { classifyOpenAIOAuthDiagnostic } from '../openaiOAuthDiagnostic'

function makeAccount(overrides: Partial<Account> = {}): Account {
  return {
    id: 1,
    name: 'account',
    platform: 'openai',
    type: 'oauth',
    proxy_id: null,
    concurrency: 1,
    priority: 1,
    status: 'active',
    error_message: null,
    last_used_at: null,
    expires_at: null,
    auto_pause_on_expired: true,
    created_at: '2026-09-23T00:00:00Z',
    updated_at: '2026-09-23T00:00:00Z',
    schedulable: true,
    rate_limited_at: null,
    rate_limit_reset_at: null,
    overload_until: null,
    temp_unschedulable_until: null,
    temp_unschedulable_reason: null,
    session_window_start: null,
    session_window_end: null,
    session_window_status: null,
    ...overrides
  }
}

describe('classifyOpenAIOAuthDiagnostic', () => {
  it('classifies explicit revoked-token errors without matching arbitrary 401 text', () => {
    expect(classifyOpenAIOAuthDiagnostic(makeAccount({
      status: 'error',
      error_message: 'Token revoked (401): upstream rejected'
    })))
      .toBe('credentials_rejected')
    expect(classifyOpenAIOAuthDiagnostic(makeAccount({ status: 'error', error_message: 'unrelated 401 in message' })))
      .toBe('other_error')
  })

  it('classifies missing refresh token and persisted OAuth 401 cooldown separately', () => {
    expect(classifyOpenAIOAuthDiagnostic(makeAccount({
      status: 'error',
      error_message: 'OAuth 401 (no refresh_token): unauthorized'
    }))).toBe('refresh_token_missing')
    expect(classifyOpenAIOAuthDiagnostic(makeAccount({
      temp_unschedulable_until: '2099-01-01T00:00:00Z',
      temp_unschedulable_reason: 'OAuth 401: invalid or expired credentials'
    }))).toBe('upstream_401_cooldown')
    expect(classifyOpenAIOAuthDiagnostic(makeAccount({
      temp_unschedulable_until: '2020-01-01T00:00:00Z',
      temp_unschedulable_reason: 'OAuth 401: invalid or expired credentials'
    }))).toBeNull()
  })

  it('classifies exhausted refresh retries and leaves other platforms out', () => {
    expect(classifyOpenAIOAuthDiagnostic(makeAccount({
      temp_unschedulable_until: '2099-01-01T00:00:00Z',
      temp_unschedulable_reason: 'token refresh retry exhausted: timeout'
    }))).toBe('refresh_retry_exhausted')
    expect(classifyOpenAIOAuthDiagnostic(makeAccount({
      status: 'error',
      error_message: 'Token refresh failed (non-retryable): invalid_client'
    }))).toBe('other_error')
    expect(classifyOpenAIOAuthDiagnostic(makeAccount({ platform: 'antigravity' }))).toBeNull()
    expect(classifyOpenAIOAuthDiagnostic(makeAccount({ type: 'apikey' }))).toBeNull()
  })
})

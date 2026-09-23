import { beforeEach, describe, expect, it, vi } from 'vitest'

const { get, put, patch, remove, post } = vi.hoisted(() => ({
  get: vi.fn(),
  put: vi.fn(),
  patch: vi.fn(),
  remove: vi.fn(),
  post: vi.fn()
}))

vi.mock('@/api/client', () => ({
  apiClient: { get, put, patch, delete: remove, post }
}))

import {
  deleteOpenAIReauthProfile,
  enqueueOpenAIReauth,
  getOpenAIReauthStatus,
  saveOpenAIReauthProfile,
  setOpenAIReauthProfileEnabled
} from '@/api/admin/accounts'

describe('admin OpenAI reauthorization API', () => {
  beforeEach(() => {
    get.mockReset().mockResolvedValue({ data: { worker_enabled: true, profile_configured: false, jobs: [] } })
    put.mockReset().mockResolvedValue({ data: { enabled: true, profile_version: 2 } })
    patch.mockReset().mockResolvedValue({ data: { enabled: false } })
    remove.mockReset().mockResolvedValue({ data: { deleted: true } })
    post.mockReset().mockResolvedValue({ data: { queued: true } })
  })

  it('reads per-account status without requesting secret fields', async () => {
    await getOpenAIReauthStatus(42)
    expect(get).toHaveBeenCalledWith('/admin/openai/accounts/42/reauth')
  })

  it('sends secrets only in the profile write request', async () => {
    const payload = { password: 'test-password', totp_secret: 'TESTTOTPSEED', enabled: false }
    const result = await saveOpenAIReauthProfile(42, payload)

    expect(put).toHaveBeenCalledWith('/admin/openai/accounts/42/reauth-profile', payload)
    expect(result).toEqual({ enabled: true, profile_version: 2 })
  })

  it('toggles a profile without resubmitting credentials', async () => {
    await setOpenAIReauthProfileEnabled(42, false)
    expect(patch).toHaveBeenCalledWith('/admin/openai/accounts/42/reauth-profile', { enabled: false })
  })

  it('supports unbinding and manual queueing', async () => {
    await deleteOpenAIReauthProfile(42)
    await enqueueOpenAIReauth(42)

    expect(remove).toHaveBeenCalledWith('/admin/openai/accounts/42/reauth-profile')
    expect(post).toHaveBeenCalledWith('/admin/openai/accounts/42/reauth')
  })
})

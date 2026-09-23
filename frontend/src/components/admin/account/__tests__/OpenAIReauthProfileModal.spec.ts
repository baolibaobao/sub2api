import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { defineComponent } from 'vue'

const {
  getOpenAIReauthStatus,
  saveOpenAIReauthProfile,
  setOpenAIReauthProfileEnabled,
  deleteOpenAIReauthProfile,
  enqueueOpenAIReauth,
  showSuccess,
  showWarning,
  showError
} = vi.hoisted(() => ({
  getOpenAIReauthStatus: vi.fn(),
  saveOpenAIReauthProfile: vi.fn(),
  setOpenAIReauthProfileEnabled: vi.fn(),
  deleteOpenAIReauthProfile: vi.fn(),
  enqueueOpenAIReauth: vi.fn(),
  showSuccess: vi.fn(),
  showWarning: vi.fn(),
  showError: vi.fn()
}))

vi.mock('@/api/admin', () => ({
  adminAPI: {
    accounts: {
      getOpenAIReauthStatus,
      saveOpenAIReauthProfile,
      setOpenAIReauthProfileEnabled,
      deleteOpenAIReauthProfile,
      enqueueOpenAIReauth
    }
  }
}))

vi.mock('@/stores/app', () => ({
  useAppStore: () => ({ showSuccess, showWarning, showError })
}))

vi.mock('vue-i18n', async () => {
  const actual = await vi.importActual<typeof import('vue-i18n')>('vue-i18n')
  return { ...actual, useI18n: () => ({ t: (key: string) => key }) }
})

import OpenAIReauthProfileModal from '../OpenAIReauthProfileModal.vue'

const BaseDialogStub = defineComponent({
  props: { show: Boolean, title: String },
  template: '<section v-if="show"><h2>{{ title }}</h2><slot /><slot name="footer" /></section>'
})

const ToggleStub = defineComponent({
  props: { modelValue: Boolean, disabled: Boolean },
  emits: ['update:modelValue'],
  template: '<button data-test="toggle" :disabled="disabled" @click="$emit(\'update:modelValue\', !modelValue)"></button>'
})

const account = { id: 42, name: 'account@example.com', platform: 'openai', type: 'oauth' } as any

function makeStatus(overrides: Record<string, unknown> = {}) {
  return {
    worker_enabled: true,
    profile_configured: true,
    profile: { account_id: 42, enabled: true, profile_version: 3, updated_at: '2026-09-24T00:00:00Z' },
    jobs: [],
    ...overrides
  }
}

function mountModal() {
  return mount(OpenAIReauthProfileModal, {
    props: { show: true, account },
    global: {
      stubs: { BaseDialog: BaseDialogStub, Toggle: ToggleStub, Icon: true }
    }
  })
}

describe('OpenAI reauthorization profile modal', () => {
  beforeEach(() => {
    getOpenAIReauthStatus.mockReset().mockResolvedValue(makeStatus())
    saveOpenAIReauthProfile.mockReset().mockResolvedValue({ enabled: true, profile_version: 4 })
    setOpenAIReauthProfileEnabled.mockReset().mockResolvedValue({ enabled: false })
    deleteOpenAIReauthProfile.mockReset().mockResolvedValue({ deleted: true })
    enqueueOpenAIReauth.mockReset().mockResolvedValue({ queued: true })
    showSuccess.mockReset()
    showWarning.mockReset()
    showError.mockReset()
  })

  it('shows phone-verification status without ever receiving stored secrets', async () => {
    getOpenAIReauthStatus.mockResolvedValue(makeStatus({
      jobs: [{
        id: 1,
        account_id: 42,
        status: 'phone_verification_required',
        error_code: 'phone_verification_required',
        message: '需要在官方页面完成手机号验证',
        attempt: 1,
        created_at: '2026-09-24T00:00:00Z'
      }]
    }))
    const wrapper = mountModal()
    await flushPromises()

    expect(getOpenAIReauthStatus).toHaveBeenCalledWith(42)
    expect(wrapper.text()).toContain('admin.accounts.openaiReauth.status.phone_verification_required')
    expect(wrapper.text()).toContain('需要在官方页面完成手机号验证')
    expect(wrapper.text()).not.toContain('test-password')
    expect(wrapper.text()).not.toContain('TESTTOTPSEED')
  })

  it('saves entered credentials and clears the secret fields on success', async () => {
    const wrapper = mountModal()
    await flushPromises()
    const passwordInput = wrapper.find('input[autocomplete="new-password"]')
    const totpInput = wrapper.find('input[autocomplete="off"]')
    await passwordInput.setValue('test-password')
    await totpInput.setValue('TESTTOTPSEED')
    await wrapper.find('#openai-reauth-profile-form').trigger('submit')
    await flushPromises()

    expect(saveOpenAIReauthProfile).toHaveBeenCalledWith(42, {
      password: 'test-password',
      totp_secret: 'TESTTOTPSEED',
      enabled: true
    })
    expect((passwordInput.element as HTMLInputElement).value).toBe('')
    expect((totpInput.element as HTMLInputElement).value).toBe('')
    expect(showSuccess).toHaveBeenCalledWith('admin.accounts.openaiReauth.saveSuccess')
  })

  it('changes enabled state without sending credentials', async () => {
    const wrapper = mountModal()
    await flushPromises()
    await wrapper.findAll('[data-test="toggle"]')[0].trigger('click')
    await flushPromises()

    expect(setOpenAIReauthProfileEnabled).toHaveBeenCalledWith(42, false)
  })
})

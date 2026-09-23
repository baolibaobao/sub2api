<template>
  <BaseDialog
    :show="show"
    :title="t('admin.accounts.openaiReauth.title')"
    width="wide"
    @close="handleClose"
  >
    <div v-if="account" class="space-y-5">
      <header class="flex flex-wrap items-center justify-between gap-3">
        <div class="min-w-0">
          <p class="truncate text-sm font-semibold text-gray-900 dark:text-gray-100">{{ account.name }}</p>
          <p class="mt-0.5 text-xs text-gray-500 dark:text-gray-400">
            {{ t('admin.accounts.openaiReauth.account') }} #{{ account.id }}
          </p>
        </div>
        <div class="flex items-center gap-2">
          <span
            v-if="status"
            class="inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-xs font-medium"
            :class="status.worker_enabled
              ? 'bg-emerald-50 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300'
              : 'bg-amber-50 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300'"
            role="status"
          >
            <span class="h-1.5 w-1.5 rounded-full" :class="status.worker_enabled ? 'bg-emerald-500' : 'bg-amber-500'" />
            {{ status.worker_enabled ? t('admin.accounts.openaiReauth.workerReady') : t('admin.accounts.openaiReauth.workerUnavailable') }}
          </span>
          <span v-else class="text-xs text-gray-500 dark:text-gray-400" role="status">
            {{ t('admin.accounts.openaiReauth.loading') }}
          </span>
          <button
            type="button"
            class="inline-flex h-8 w-8 items-center justify-center rounded-md text-gray-500 hover:bg-gray-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary-500 dark:hover:bg-dark-700"
            :aria-label="t('admin.accounts.openaiReauth.refresh')"
            :title="t('admin.accounts.openaiReauth.refresh')"
            :disabled="loading"
            @click="loadStatus(true)"
          >
            <Icon name="refresh" size="sm" :class="loading ? 'animate-spin' : ''" />
          </button>
        </div>
      </header>

      <div v-if="status && !status.worker_enabled" class="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-800 dark:border-amber-800/60 dark:bg-amber-900/20 dark:text-amber-200" role="alert">
        {{ t('admin.accounts.openaiReauth.workerUnavailable') }}
      </div>

      <div v-if="loading && !status" class="flex items-center justify-center gap-2 py-8 text-sm text-gray-500 dark:text-gray-400">
        <Icon name="refresh" size="sm" class="animate-spin" />
        {{ t('admin.accounts.openaiReauth.loading') }}
      </div>

      <div v-else-if="loadError && !status" class="flex flex-wrap items-center justify-between gap-3 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-900/60 dark:bg-red-950/30 dark:text-red-300" role="alert">
        <span>{{ loadError }}</span>
        <button type="button" class="btn btn-secondary btn-sm" @click="loadStatus(true)">
          {{ t('admin.accounts.openaiReauth.retry') }}
        </button>
      </div>

      <template v-else-if="status">
        <section class="flex flex-wrap items-center justify-between gap-4 border-y border-gray-200 py-3 dark:border-dark-600">
          <div class="min-w-0">
            <p class="text-sm font-medium text-gray-900 dark:text-gray-100">
              {{ status.profile_configured ? t('admin.accounts.openaiReauth.bound') : t('admin.accounts.openaiReauth.unbound') }}
            </p>
            <p v-if="status.profile" class="mt-1 text-xs text-gray-500 dark:text-gray-400">
              v{{ status.profile.profile_version }} · {{ formatDateTime(status.profile.updated_at) }}
            </p>
          </div>
          <div v-if="status.profile_configured && status.profile" class="flex flex-wrap items-center gap-3">
            <label class="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
              <Toggle
                :model-value="status.profile.enabled"
                :disabled="changingEnabled || (!status.profile.enabled && !status.worker_enabled)"
                @update:model-value="handleEnabledChange"
              />
              {{ t('admin.accounts.openaiReauth.enabled') }}
            </label>
            <button
              v-if="status.worker_enabled && status.profile.enabled"
              type="button"
              class="btn btn-secondary btn-sm inline-flex items-center gap-1.5"
              :disabled="enqueueing"
              @click="handleEnqueue"
            >
              <Icon name="play" size="xs" />
              {{ t('admin.accounts.openaiReauth.queue') }}
            </button>
          </div>
        </section>

        <form id="openai-reauth-profile-form" class="space-y-3" @submit.prevent="handleSave">
          <div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <label class="block min-w-0">
              <span class="mb-1 block text-xs font-medium text-gray-700 dark:text-gray-300">
                {{ t('admin.accounts.openaiReauth.password') }}
              </span>
              <input
                v-model="password"
                type="password"
                autocomplete="new-password"
                maxlength="1024"
                class="form-input w-full"
                :disabled="!status.worker_enabled || saving"
                required
              />
            </label>
            <label class="block min-w-0">
              <span class="mb-1 block text-xs font-medium text-gray-700 dark:text-gray-300">
                {{ t('admin.accounts.openaiReauth.totpSecret') }}
              </span>
              <input
                v-model="totpSecret"
                type="password"
                autocomplete="off"
                maxlength="128"
                class="form-input w-full"
                :disabled="!status.worker_enabled || saving"
                required
              />
            </label>
          </div>
          <p class="text-xs text-gray-500 dark:text-gray-400">
            {{ t('admin.accounts.openaiReauth.replaceCredentials') }}
          </p>
          <label class="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
            <Toggle v-model="enabledAfterSave" :disabled="!status.worker_enabled || saving" />
            {{ t('admin.accounts.openaiReauth.enabled') }}
          </label>
        </form>

        <div v-if="status.profile_configured" class="space-y-2">
          <div v-if="confirmRemove" class="flex flex-wrap items-center justify-between gap-3 rounded-md border border-red-200 bg-red-50 px-3 py-2 dark:border-red-900/60 dark:bg-red-950/30">
            <p class="min-w-0 flex-1 text-sm text-red-800 dark:text-red-200">
              {{ t('admin.accounts.openaiReauth.removeConfirm') }}
            </p>
            <div class="flex items-center gap-2">
              <button type="button" class="btn btn-secondary btn-sm" @click="confirmRemove = false">
                {{ t('common.cancel') }}
              </button>
              <button type="button" class="btn btn-danger btn-sm" :disabled="removing" @click="handleRemove">
                {{ t('admin.accounts.openaiReauth.confirmRemove') }}
              </button>
            </div>
          </div>
          <button
            v-else
            type="button"
            class="inline-flex items-center gap-1.5 text-sm text-red-600 hover:text-red-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-500 dark:text-red-400"
            :disabled="removing"
            @click="confirmRemove = true"
          >
            <Icon name="trash" size="sm" />
            {{ t('admin.accounts.openaiReauth.remove') }}
          </button>
        </div>

        <section class="space-y-2">
          <h4 class="text-sm font-semibold text-gray-900 dark:text-gray-100">
            {{ t('admin.accounts.openaiReauth.jobs') }}
          </h4>
          <p v-if="status.jobs.length === 0" class="py-3 text-sm text-gray-500 dark:text-gray-400">
            {{ t('admin.accounts.openaiReauth.noJobs') }}
          </p>
          <ul v-else class="divide-y divide-gray-100 dark:divide-dark-700">
            <li v-for="job in status.jobs" :key="job.id" class="flex flex-wrap items-start justify-between gap-x-4 gap-y-2 py-3">
              <div class="min-w-0 flex-1">
                <div class="flex flex-wrap items-center gap-2">
                  <span class="rounded px-2 py-0.5 text-xs font-medium" :class="jobStatusClass[job.status]">
                    {{ t(jobStatusKey[job.status]) }}
                  </span>
                  <span v-if="job.error_code" class="font-mono text-xs text-gray-500 dark:text-gray-400">{{ job.error_code }}</span>
                </div>
                <p v-if="job.message" class="mt-1 break-words text-sm text-gray-600 dark:text-gray-300">{{ job.message }}</p>
              </div>
              <div class="shrink-0 text-right text-xs text-gray-500 dark:text-gray-400">
                <p>{{ formatDateTime(job.created_at) }}</p>
                <p class="mt-1">{{ t('admin.accounts.openaiReauth.attempt', { count: job.attempt }) }}</p>
              </div>
            </li>
          </ul>
        </section>
      </template>
    </div>

    <template #footer>
      <button type="button" class="btn btn-secondary" @click="handleClose">{{ t('common.close') }}</button>
      <button
        v-if="status"
        type="submit"
        form="openai-reauth-profile-form"
        class="btn btn-primary inline-flex items-center gap-1.5"
        :disabled="!status.worker_enabled || saving || !password || !totpSecret"
      >
        <Icon v-if="saving" name="refresh" size="sm" class="animate-spin" />
        {{ saving ? t('admin.accounts.openaiReauth.saving') : t('admin.accounts.openaiReauth.save') }}
      </button>
    </template>
  </BaseDialog>
</template>

<script setup lang="ts">
import { computed, onUnmounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { adminAPI } from '@/api/admin'
import type { OpenAIReauthJobStatus, OpenAIReauthStatus } from '@/api/admin/accounts'
import { useAppStore } from '@/stores/app'
import BaseDialog from '@/components/common/BaseDialog.vue'
import Toggle from '@/components/common/Toggle.vue'
import Icon from '@/components/icons/Icon.vue'
import type { Account } from '@/types'
import { formatDateTime } from '@/utils/format'
import { extractApiErrorMessage } from '@/utils/apiError'

const props = defineProps<{ show: boolean; account: Account | null }>()
const emit = defineEmits<{ (event: 'close'): void }>()

const { t } = useI18n()
const appStore = useAppStore()
const status = ref<OpenAIReauthStatus | null>(null)
const loading = ref(false)
const loadError = ref('')
const saving = ref(false)
const changingEnabled = ref(false)
const enqueueing = ref(false)
const removing = ref(false)
const confirmRemove = ref(false)
const password = ref('')
const totpSecret = ref('')
const enabledAfterSave = ref(false)
let pollTimer: ReturnType<typeof setTimeout> | null = null
let loadGeneration = 0

const jobStatusKey: Record<OpenAIReauthJobStatus, string> = {
  queued: 'admin.accounts.openaiReauth.status.queued',
  running: 'admin.accounts.openaiReauth.status.running',
  needs_input: 'admin.accounts.openaiReauth.status.needs_input',
  succeeded: 'admin.accounts.openaiReauth.status.succeeded',
  failed: 'admin.accounts.openaiReauth.status.failed',
  phone_verification_required: 'admin.accounts.openaiReauth.status.phone_verification_required',
  cancelled: 'admin.accounts.openaiReauth.status.cancelled'
}

const jobStatusClass: Record<OpenAIReauthJobStatus, string> = {
  queued: 'bg-sky-50 text-sky-700 dark:bg-sky-900/30 dark:text-sky-300',
  running: 'bg-amber-50 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
  needs_input: 'bg-violet-50 text-violet-700 dark:bg-violet-900/30 dark:text-violet-300',
  succeeded: 'bg-emerald-50 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300',
  failed: 'bg-red-50 text-red-700 dark:bg-red-900/30 dark:text-red-300',
  phone_verification_required: 'bg-orange-50 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
  cancelled: 'bg-gray-100 text-gray-600 dark:bg-dark-700 dark:text-gray-300'
}

const hasActiveJob = computed(() => status.value?.jobs.some((job) => job.status === 'queued' || job.status === 'running') ?? false)

function clearPollTimer(): void {
  if (pollTimer) clearTimeout(pollTimer)
  pollTimer = null
}

function schedulePoll(): void {
  clearPollTimer()
  if (!props.show || !hasActiveJob.value) return
  pollTimer = setTimeout(() => void loadStatus(), 5000)
}

function clearSecrets(): void {
  password.value = ''
  totpSecret.value = ''
}

async function loadStatus(initializeProfile = false): Promise<void> {
  if (!props.show || !props.account || loading.value) return
  const generation = ++loadGeneration
  const accountID = props.account.id
  loading.value = true
  loadError.value = ''
  try {
    const nextStatus = await adminAPI.accounts.getOpenAIReauthStatus(accountID)
    if (generation !== loadGeneration || !props.show || props.account?.id !== accountID) return
    status.value = nextStatus
    if (initializeProfile) enabledAfterSave.value = status.value.profile?.enabled ?? false
  } catch (error) {
    if (generation === loadGeneration) {
      loadError.value = extractApiErrorMessage(error, t('admin.accounts.openaiReauth.loadFailed'))
    }
  } finally {
    if (generation === loadGeneration) {
      loading.value = false
      schedulePoll()
    }
  }
}

async function handleSave(): Promise<void> {
  if (!props.account || !status.value?.worker_enabled || !password.value || !totpSecret.value || saving.value) return
  saving.value = true
  try {
    await adminAPI.accounts.saveOpenAIReauthProfile(props.account.id, {
      password: password.value,
      totp_secret: totpSecret.value,
      enabled: enabledAfterSave.value
    })
    clearSecrets()
    confirmRemove.value = false
    appStore.showSuccess(t('admin.accounts.openaiReauth.saveSuccess'))
    await loadStatus(true)
  } catch (error) {
    appStore.showError(extractApiErrorMessage(error, t('admin.accounts.openaiReauth.saveFailed')))
  } finally {
    saving.value = false
  }
}

async function handleEnabledChange(enabled: boolean): Promise<void> {
  if (!props.account || !status.value?.profile_configured || changingEnabled.value) return
  changingEnabled.value = true
  try {
    await adminAPI.accounts.setOpenAIReauthProfileEnabled(props.account.id, enabled)
    await loadStatus(true)
  } catch (error) {
    appStore.showError(extractApiErrorMessage(error, t('admin.accounts.openaiReauth.enableFailed')))
    await loadStatus(true)
  } finally {
    changingEnabled.value = false
  }
}

async function handleEnqueue(): Promise<void> {
  if (!props.account || enqueueing.value || !status.value?.worker_enabled || !status.value.profile?.enabled) return
  enqueueing.value = true
  try {
    const result = await adminAPI.accounts.enqueueOpenAIReauth(props.account.id)
    if (result.queued) appStore.showSuccess(t('admin.accounts.openaiReauth.queued'))
    else appStore.showWarning(t('admin.accounts.openaiReauth.notQueued'))
    await loadStatus()
  } catch (error) {
    appStore.showError(extractApiErrorMessage(error, t('admin.accounts.openaiReauth.queueFailed')))
  } finally {
    enqueueing.value = false
  }
}

async function handleRemove(): Promise<void> {
  if (!props.account || removing.value || !status.value?.profile_configured) return
  removing.value = true
  try {
    await adminAPI.accounts.deleteOpenAIReauthProfile(props.account.id)
    clearSecrets()
    confirmRemove.value = false
    appStore.showSuccess(t('admin.accounts.openaiReauth.removeSuccess'))
    await loadStatus(true)
  } catch (error) {
    appStore.showError(extractApiErrorMessage(error, t('admin.accounts.openaiReauth.removeFailed')))
  } finally {
    removing.value = false
  }
}

function handleClose(): void {
  clearSecrets()
  confirmRemove.value = false
  clearPollTimer()
  emit('close')
}

watch(
  () => [props.show, props.account?.id] as const,
  ([show]) => {
    loadGeneration += 1
    loading.value = false
    clearPollTimer()
    clearSecrets()
    confirmRemove.value = false
    status.value = null
    loadError.value = ''
    if (show) void loadStatus(true)
  },
  { immediate: true }
)

onUnmounted(() => {
  clearPollTimer()
  clearSecrets()
})
</script>

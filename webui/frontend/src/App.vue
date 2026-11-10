<script setup>
import { ref } from 'vue'
import AdminLayout from '@/layouts/AdminLayout.vue'
import { getStoredAccount, setStoredAccount, clearStoredAccount } from '@/accountMode.js'

const account = ref(getStoredAccount())

function selectAccount(value) {
  account.value = setStoredAccount(value)
}

function switchAccount() {
  clearStoredAccount()
  account.value = null
}
</script>

<template>
  <div v-if="!account" class="gate">
    <div class="card">
      <h1>Select Account</h1>
      <p>Choose a workspace to continue</p>
      <div class="actions">
        <button type="button" class="primary" @click="selectAccount('1')">Account 1</button>
        <button type="button" @click="selectAccount('2')">Account 2</button>
      </div>
    </div>
  </div>
  <AdminLayout v-else :account="account" @switch-account="switchAccount" />
</template>

<style scoped>
.gate { min-height: 100vh; display: grid; place-items: center; background: #f4f6fb; padding: 24px; }
.card { width: min(440px, 100%); background: #fff; border: 1px solid #e6e8ef; border-radius: 14px; padding: 40px 32px; text-align: center; box-shadow: 0 16px 40px rgba(31,42,68,.1); }
h1 { margin: 0 0 8px; color: #1f2a44; }
p { margin: 0; color: #7b8498; }
.actions { display: flex; gap: 12px; justify-content: center; margin-top: 28px; }
button { min-width: 132px; height: 40px; border-radius: 8px; border: 1px solid #c9d3ea; background: #fff; cursor: pointer; }
button.primary { background: #2563eb; border-color: #2563eb; color: #fff; }
</style>
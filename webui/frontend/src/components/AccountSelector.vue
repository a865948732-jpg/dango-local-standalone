<script setup>
defineEmits(['select'])
</script>

<template>
  <main class="account-selector">
    <section class="selector-card">
      <div class="selector-icon">*</div>
      <h1>选择账户</h1>
      <p>请选择要进入的独立工作区</p>
      <div class="account-actions">
        <button type="button" class="btn primary" @click="('select', '1')">账户 1</button>
        <button type="button" class="btn" @click="('select', '2')">账户 2</button>
      </div>
    </section>
  </main>
</template>

<style scoped>
.account-selector { min-height: 100vh; display: grid; place-items: center; padding: 24px; background: #f4f6fb; }
.selector-card { width: min(440px, 100%); padding: 40px 32px; text-align: center; background: #fff; border: 1px solid #e6e8ef; border-radius: 14px; box-shadow: 0 16px 40px rgba(31, 42, 68, .1); }
.selector-icon { font-size: 42px; line-height: 1; color: #2563eb; font-weight: 700; }
h1 { margin: 16px 0 8px; color: #1f2a44; font-size: 24px; }
p { margin: 0; color: #7b8498; }
.account-actions { display: flex; gap: 12px; justify-content: center; margin-top: 28px; }
.btn { min-width: 132px; height: 40px; border-radius: 8px; border: 1px solid #c9d3ea; background: #fff; color: #1f2a44; font-size: 15px; cursor: pointer; }
.btn.primary { background: #2563eb; border-color: #2563eb; color: #fff; }
</style>
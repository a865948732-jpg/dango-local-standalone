import { createApp } from 'vue'
import { createPinia } from 'pinia'

import 'element-plus/dist/index.css'
import 'element-plus/theme-chalk/dark/css-vars.css'
import './styles/theme.css'
import 'nprogress/nprogress.css'

import {
  Platform, Fold, Expand, Moon, Sunny, User, ArrowDown,
  Odometer, Upload, VideoPlay, MagicStick, Connection, Files,
  CircleCheck, CreditCard, Document, Message, Iphone, Share,
  Loading, Select, CircleClose, Refresh, CopyDocument,
  Bell, Close, Download, Menu, Switch, DocumentChecked,
} from '@element-plus/icons-vue'

import App from './App.vue'
import router from './router'

const ICONS = {
  Platform, Fold, Expand, Moon, Sunny, User, ArrowDown,
  Odometer, Upload, VideoPlay, MagicStick, Connection, Files,
  CircleCheck, CreditCard, Document, Message, Iphone, Share,
  Loading, Select, CircleClose, Refresh, CopyDocument,
  Bell, Close, Download, Menu, Switch, DocumentChecked,
}

const app = createApp(App)
for (const [name, comp] of Object.entries(ICONS)) app.component(name, comp)

app.config.errorHandler = (err, instance, info) => {
  console.error('VueError', err, info)
  const el = document.getElementById('boot-error')
  if (el) {
    el.style.display = 'block'
    el.textContent = 'VueError: ' + (err && (err.stack || err.message || err)) + '\ninfo=' + info
  }
}

app.use(createPinia())
app.use(router)
app.mount('#app')
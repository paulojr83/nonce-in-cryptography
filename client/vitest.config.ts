import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  // The relay babel plugin must run in tests too, otherwise the graphql``
  // tags in imported modules are never rewritten to their artifacts
  plugins: [
    react({
      babel: {
        plugins: [['relay', { artifactDirectory: './src/__generated__' }]],
      },
    }),
  ],
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: [
        'node_modules/',
        'src/test/',
        '__generated__/',
      ],
    },
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
})

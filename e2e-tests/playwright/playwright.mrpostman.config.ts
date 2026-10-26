// mrpostman (docs/testing/UPSTREAM-E2E.md): the upstream config minus what needs plugins — the stock global setup's
// plugin reset (GET /plugins is 501 with PluginSettings.Enable=false) and the `setup` project the chrome project depends on.
// Run: npx playwright test --config playwright.mrpostman.config.ts --grep @smoke --project=chrome
import {defineConfig} from '@playwright/test';

import base from './playwright.config';

export default defineConfig({
    ...base,
    globalSetup: './global_setup.mrpostman.ts',
    projects: (base.projects ?? []).filter((p) => p.name === 'chrome').map((p) => ({...p, dependencies: []})),
});

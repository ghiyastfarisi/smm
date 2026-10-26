// mrpostman: baseGlobalSetup() without the plugin reset (plugins are disabled by env on this deployment) and without
// creating the "ad-1" default team (the smoke specs create their own teams through pw.initSetup()). Expects the seeded
// sysadmin (PW_ADMIN_USERNAME / PW_ADMIN_PASSWORD) to exist; the per-test fixture still runs resetConfig()/resetRoles().
import {clearGlobalSetupFailure, getAdminClient, recordGlobalSetupFailure, testConfig} from '@mattermost/playwright-lib';

async function globalSetup() {
    clearGlobalSetupFailure();
    try {
        const {adminClient, adminUser} = await getAdminClient({skipLog: true});
        if (!adminUser) {
            throw new Error(`cannot log in as ${testConfig.adminUsername}`);
        }
        // Same onboarding preferences the upstream setup gives the admin: the tour overlay otherwise swallows clicks.
        const id = adminUser.id;
        await adminClient.savePreferences(id, [
            {user_id: id, category: 'tutorial_step', name: id, value: '999'},
            {user_id: id, category: 'crt_thread_pane_step', name: id, value: '999'},
            {user_id: id, category: 'onboarding_task_list', name: 'onboarding_task_list_show', value: 'false'},
            {user_id: id, category: 'onboarding_task_list', name: 'onboarding_task_list_open', value: 'false'},
        ]);
    } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        recordGlobalSetupFailure(`Global setup failed: ${message}\nEnsure the server at ${testConfig.baseURL} is running.`);
    }
}

export default globalSetup;

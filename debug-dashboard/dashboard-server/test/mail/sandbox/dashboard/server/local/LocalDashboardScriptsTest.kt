package mail.sandbox.dashboard.server.local

import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.isExecutable
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class LocalDashboardScriptsTest {
    private val dashboardRoot: Path = Path.of(System.getProperty("user.dir"))
        .toAbsolutePath()
        .normalize()
        .let { working ->
            if (working.fileName?.toString() == "dashboard-server") working.parent else working
        }

    @Test
    fun localLauncherUsesOnlyTheKotlinToolchainAndDedicatedProviderStack() {
        val script = dashboardRoot.resolve("start-local.sh")

        assertTrue(Files.isRegularFile(script), "start-local.sh is missing")
        assertTrue(script.isExecutable(), "start-local.sh must be executable")
        val source = script.readText()

        assertTrue("docker-compose.local-providers.yml" in source)
        assertTrue("up -d --wait dovecot postfix oauth2-mock" in source)
        assertTrue("start-local-stalwart.sh" in source)
        assertTrue(
            "dashboard_provider_root=\"${'$'}dashboard_root/.runtime/local-providers\"" in source,
        )
        assertTrue("chmod 0700 \"${'$'}dashboard_provider_root\"" in source)
        assertTrue("chmod 0700 \"${'$'}dashboard_dovecot_runtime\"" in source)
        assertTrue("chmod 0777 \"${'$'}dashboard_provider_vmail\"" in source)
        assertTrue("\"${'$'}dashboard_kotlin\" build --module dashboard-web" in source)
        assertTrue("DASHBOARD_WEB_ASSETS=" in source)
        assertTrue("DASHBOARD_WEB_RESOURCES=" in source)
        assertTrue("DASHBOARD_WEB_ENTRY=dashboard-web.mjs" in source)
        assertTrue("\"${'$'}dashboard_kotlin\" run" in source)
        assertTrue("--module dashboard-server" in source)
        assertTrue("--working-dir=\"${'$'}dashboard_repository_root\"" in source)
        assertFalse(Regex("\\b(?:gradle|npm|node|yarn|pnpm)\\b").containsMatchIn(source))
    }

    @Test
    fun localProviderOverlayUsesDedicatedLoopbackPorts() {
        val overlay = dashboardRoot.resolve("docker-compose.local-providers.yml")

        assertTrue(Files.isRegularFile(overlay), "local provider overlay is missing")
        val source = overlay.readText()
        assertTrue(source.count { it == '!' } >= 3)
        assertTrue("127.0.0.1:21143:31143" in source)
        assertTrue("127.0.0.1:21993:31993" in source)
        assertTrue("127.0.0.1:21025:25" in source)
        assertTrue("127.0.0.1:28080:8080" in source)
        assertTrue(
            "./debug-dashboard/.runtime/local-providers/dovecot:/etc/dovecot/runtime:ro" in
                source,
        )
        assertTrue(
            "./debug-dashboard/.runtime/local-providers/vmail:/srv/vmail" in source,
        )
        assertTrue(
            "./debug-dashboard/.runtime/local-providers/logs:/var/log/dovecot" in source,
        )
        assertFalse("- ./vmail:/srv/vmail" in source)
        assertFalse("- ./logs:/var/log/dovecot" in source)
        assertFalse("8443" in source)
    }

    @Test
    fun localBackendRoutesDovecotThroughItsValidatedRepositoryRoot() {
        val source = dashboardRoot.resolve(
            "dashboard-server/src/mail/sandbox/dashboard/server/local/LocalDashboardBackend.kt",
        ).readText()

        assertTrue("DovecotProductAdapter.dashboard(repositoryRoot)" in source)
    }

    @Test
    fun dedicatedStalwartLauncherBootstrapsOnceAndNeverTouchesNormalData() {
        val script = dashboardRoot.resolve("start-local-stalwart.sh")

        assertTrue(Files.isRegularFile(script), "start-local-stalwart.sh is missing")
        assertTrue(script.isExecutable(), "start-local-stalwart.sh must be executable")
        val source = script.readText()

        assertTrue("mail-sandbox-stalwart-gate" in source)
        assertTrue("stalwart-gate0b" in source)
        assertTrue("local_base_compose=\"${'$'}local_fixture_root/compose.yml\"" in source)
        assertTrue("StalwartFixturePrepareLiveTest" in source)
        assertTrue("StalwartBootstrapLiveTest" in source)
        assertTrue("StalwartRecoveryRetirementLiveTest" in source)
        assertTrue("test -f \"${'$'}local_fixture_secrets\"" in source)
        assertTrue("local_store_marker=\"${'$'}local_runtime_root/data/CURRENT\"" in source)
        assertTrue("local_ready_marker=\"${'$'}local_runtime_root/dashboard-ready\"" in source)
        assertTrue(": > \"${'$'}local_ready_marker\"" in source)
        assertFalse("StalwartGateCleanupLiveTest" in source)
        assertFalse("stalwart-data" in source)
        assertFalse("docker-compose.yml" in source)
    }
}

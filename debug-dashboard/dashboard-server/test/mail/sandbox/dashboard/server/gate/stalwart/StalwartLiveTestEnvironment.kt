package mail.sandbox.dashboard.server.gate.stalwart

import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.request.get
import java.net.URI
import java.nio.file.Path
import kotlinx.coroutines.delay
import mail.sandbox.dashboard.server.provider.stalwart.credential.CredentialStorePaths

internal object StalwartGateActionSelection {
    private val liveEnvironmentKeys = setOf(
        "STALWART_LIVE_TESTS",
        "STALWART_BASE_URL",
        "STALWART_GATE_FIXTURE_SECRETS_FILE",
    )
    private val actionEnvironmentKeys = setOf(
        "STALWART_GATE_PREPARE",
        "STALWART_GATE_CLEANUP",
        "STALWART_GATE_PHASE",
    )
    private val mailAccessEnvironmentKeys = setOf(
        "STALWART_GATE_CREDENTIAL_ROOT",
        "STALWART_GATE_RESTART_PHASE",
    )
    private val gateEnvironmentKeys =
        liveEnvironmentKeys + actionEnvironmentKeys +
            mailAccessEnvironmentKeys

    fun requirePrepare(environment: Map<String, String> = System.getenv()) {
        requireExactAction(
            environment = environment,
            selectedKey = "STALWART_GATE_PREPARE",
        )
    }

    fun requireCleanup(environment: Map<String, String> = System.getenv()) {
        requireExactAction(
            environment = environment,
            selectedKey = "STALWART_GATE_CLEANUP",
        )
    }

    fun requireLive(environment: Map<String, String>) {
        require(
            actionEnvironmentKeys.none(environment::containsKey),
        ) {
            "Selected live gate environment conflicts with an action selector"
        }
    }

    private fun requireExactAction(
        environment: Map<String, String>,
        selectedKey: String,
    ) {
        require(environment[selectedKey] == "1") {
            "$selectedKey=1 is required for the selected gate action"
        }
        require(
            (gateEnvironmentKeys - selectedKey).none(environment::containsKey),
        ) {
            "Selected gate action has conflicting gate environment"
        }
    }
}

internal enum class StalwartMailAccessRestartPhase(
    val environmentValue: String,
) {
    Staged("staged"),
    Retiring("retiring"),
    RemovalPending("removal-pending"),
}

internal data class StalwartMailAccessLiveEnvironment(
    val live: StalwartLiveTestEnvironment,
    val credentialPaths: CredentialStorePaths,
    val restartPhase: StalwartMailAccessRestartPhase?,
) {
    companion object {
        fun lifecycle(
            environment: Map<String, String> = System.getenv(),
            projectRoot: Path,
        ): StalwartMailAccessLiveEnvironment {
            require(!environment.containsKey("STALWART_GATE_RESTART_PHASE")) {
                "Lifecycle live gate forbids a restart phase"
            }
            return load(
                environment = environment,
                projectRoot = projectRoot,
                restartPhase = null,
            )
        }

        fun restart(
            environment: Map<String, String> = System.getenv(),
            projectRoot: Path,
        ): StalwartMailAccessLiveEnvironment {
            val value = environment["STALWART_GATE_RESTART_PHASE"]
                ?: throw IllegalArgumentException(
                    "STALWART_GATE_RESTART_PHASE is required",
                )
            val phase = StalwartMailAccessRestartPhase.entries.singleOrNull {
                it.environmentValue == value
            } ?: throw IllegalArgumentException(
                "STALWART_GATE_RESTART_PHASE is invalid",
            )
            return load(
                environment = environment,
                projectRoot = projectRoot,
                restartPhase = phase,
            )
        }

        private fun load(
            environment: Map<String, String>,
            projectRoot: Path,
            restartPhase: StalwartMailAccessRestartPhase?,
        ): StalwartMailAccessLiveEnvironment {
            val configuredRoot = environment["STALWART_GATE_CREDENTIAL_ROOT"]
                ?.takeIf(String::isNotBlank)
                ?.let(Path::of)
                ?: throw IllegalArgumentException(
                    "STALWART_GATE_CREDENTIAL_ROOT is required",
                )
            return StalwartMailAccessLiveEnvironment(
                live = StalwartLiveTestEnvironment.load(
                    environment = environment,
                    projectRoot = projectRoot,
                ),
                credentialPaths = CredentialStorePaths.gate0bTesting(
                    dashboardProjectRoot = projectRoot,
                    configuredRoot = configuredRoot,
                ),
                restartPhase = restartPhase,
            )
        }
    }
}

internal data class StalwartLiveTestEnvironment(
    val baseUrl: URI,
    val fixtureSecretsPath: Path,
) {
    suspend fun awaitReady() {
        val client = HttpClient(CIO) {
            install(HttpTimeout) {
                requestTimeoutMillis = 1_000
                connectTimeoutMillis = 1_000
                socketTimeoutMillis = 1_000
            }
        }
        try {
            awaitReady(
                maxAttempts = 30,
                delayMillis = 500,
            ) { url ->
                client.get(url.toString()).status.value == 200
            }
        } finally {
            client.close()
        }
    }

    suspend fun awaitReady(
        maxAttempts: Int = 30,
        delayMillis: Long = 1_000,
        probe: suspend (URI) -> Boolean,
    ) {
        require(maxAttempts in 1..60) { "Readiness attempt bound is invalid" }
        require(delayMillis in 0..5_000) { "Readiness delay bound is invalid" }
        val readinessUrl = baseUrl.resolve("/healthz/ready")
        repeat(maxAttempts) { attempt ->
            if (runCatching { probe(readinessUrl) }.getOrDefault(false)) {
                return
            }
            if (attempt + 1 < maxAttempts && delayMillis > 0) {
                delay(delayMillis)
            }
        }
        throw IllegalStateException(
            "Stalwart did not become ready at the dedicated loopback endpoint",
        )
    }

    companion object {
        fun load(
            environment: Map<String, String> = System.getenv(),
            projectRoot: Path,
        ): StalwartLiveTestEnvironment {
            StalwartGateActionSelection.requireLive(environment)
            require(environment["STALWART_LIVE_TESTS"] == "1") {
                "STALWART_LIVE_TESTS=1 is required for the selected live gate"
            }
            val baseUrlText = environment["STALWART_BASE_URL"]?.takeIf { it.isNotBlank() }
                ?: throw IllegalArgumentException("STALWART_BASE_URL is required")
            val baseUrl = runCatching { URI(baseUrlText) }
                .getOrElse { throw IllegalArgumentException("STALWART_BASE_URL is invalid") }
            require(
                baseUrl == URI("http://127.0.0.1:18443"),
            ) {
                "STALWART_BASE_URL must be the dedicated loopback gate endpoint"
            }
            return StalwartLiveTestEnvironment(
                baseUrl = baseUrl,
                fixtureSecretsPath = StalwartGateSecretFiles.fixtureSecretsPath(
                    projectRoot = projectRoot,
                    environment = environment,
                ),
            )
        }
    }
}

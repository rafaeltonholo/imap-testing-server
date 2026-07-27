package mail.sandbox.dashboard.server.gate.stalwart

import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.request.get
import java.net.URI
import java.nio.file.Path
import kotlinx.coroutines.delay

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
    private val gateEnvironmentKeys = liveEnvironmentKeys + actionEnvironmentKeys

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

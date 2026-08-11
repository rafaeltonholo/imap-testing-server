package mail.sandbox.dashboard.server.gate.stalwart

import java.net.URI

internal enum class StalwartEndpointProfile(
    val baseUrl: URI,
    val apiUrl: URI,
) {
    GATE_FIXTURE(
        baseUrl = URI("http://127.0.0.1:18443"),
        apiUrl = URI("http://127.0.0.1:18443/jmap/"),
    ),
    MIGRATION_BOOTSTRAP(
        baseUrl = URI("http://127.0.0.1:8443"),
        apiUrl = URI("http://127.0.0.1:8443/jmap/"),
    ),
    NORMAL_RUNTIME(
        baseUrl = URI("http://127.0.0.1:8443"),
        apiUrl = URI("http://127.0.0.1:8443/jmap/"),
    ),
    ;

    companion object {
        internal fun fromBaseUrl(value: URI): StalwartEndpointProfile = when {
            value == GATE_FIXTURE.baseUrl ||
                value == GATE_FIXTURE.baseUrl.resolve("/") -> GATE_FIXTURE

            value == NORMAL_RUNTIME.baseUrl ||
                value == NORMAL_RUNTIME.baseUrl.resolve("/") -> NORMAL_RUNTIME

            else -> throw IllegalArgumentException(
                "Stalwart gate base URL must be a dedicated loopback endpoint",
            )
        }
    }
}

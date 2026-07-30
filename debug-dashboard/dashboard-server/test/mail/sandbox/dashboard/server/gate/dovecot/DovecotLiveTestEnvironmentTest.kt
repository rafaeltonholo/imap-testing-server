package mail.sandbox.dashboard.server.gate.dovecot

import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class DovecotLiveTestEnvironmentTest {
    private val repositoryRoot = repositoryRoot()
    private val validEnvironment = mapOf(
        "DOVECOT_LIVE_TESTS" to "1",
        "DOVECOT_LIVE_PROFILE" to "task5-proof",
        "COMPOSE_PROJECT_NAME" to "mail-sandbox-task5-proof",
        "COMPOSE_DISABLE_ENV_FILE" to "1",
        "DOCKER_HOST" to "unix:///var/run/docker.sock",
        "COMPOSE_FILE" to (
            "docker-compose.yml" +
                File.pathSeparator +
                "debug-dashboard/dashboard-server/testResources/" +
                "dovecot-gate0c/compose.task5-proof.yml"
            ),
    )

    @Test
    fun liveEnvironmentRequiresTheSingleFixedProofProfile() {
        val live = DovecotLiveTestEnvironment.load(
            environment = validEnvironment,
            repositoryRoot = repositoryRoot,
        )

        assertEquals("127.0.0.1", live.loopbackAddress)
        assertEquals(1993, live.ordinaryImapsPort)
        assertEquals(2993, live.operatorImapsPort)
        assertEquals(21025, live.smtpPort)
        assertEquals(28080, live.oauthPort)
        assertEquals(
            repositoryRoot.resolve(
                "debug-dashboard/.runtime/task5-proof/ssl/tls.crt",
            ),
            live.tlsCertificate,
        )
        assertEquals(
            repositoryRoot.resolve(
                "debug-dashboard/.runtime/task5-proof/ssl/tls.key",
            ),
            live.profile.tlsPrivateKey,
        )
        assertEquals(
            repositoryRoot.resolve(
                "debug-dashboard/dashboard-server/testResources/" +
                    "dovecot-gate0c/compose.task5-proof.yml",
            ),
            live.composeOverride,
        )

        listOf(
            emptyMap(),
            validEnvironment - "DOVECOT_LIVE_TESTS",
            validEnvironment + ("DOVECOT_LIVE_TESTS" to "true"),
            validEnvironment - "DOVECOT_LIVE_PROFILE",
            validEnvironment + ("DOVECOT_LIVE_PROFILE" to "normal"),
            validEnvironment - "COMPOSE_PROJECT_NAME",
            validEnvironment + ("COMPOSE_PROJECT_NAME" to "mail-sandbox"),
            validEnvironment - "COMPOSE_DISABLE_ENV_FILE",
            validEnvironment + ("COMPOSE_DISABLE_ENV_FILE" to "true"),
            validEnvironment - "COMPOSE_FILE",
            validEnvironment + ("COMPOSE_FILE" to "docker-compose.yml"),
            validEnvironment - "DOCKER_HOST",
            validEnvironment + ("DOVECOT_IMAPS_PORT" to "1993"),
            validEnvironment + ("DOVECOT_OPERATOR_HOST" to "127.0.0.1"),
            validEnvironment + ("COMPOSE_PROFILES" to "stalwart"),
            validEnvironment + ("COMPOSE_PROJECT_DIR" to repositoryRoot.toString()),
            validEnvironment + ("DOCKER_CONTEXT" to "remote"),
            validEnvironment + ("DOCKER_HOST" to "tcp://127.0.0.1:2375"),
        ).forEach { invalid ->
            assertFailsWith<IllegalArgumentException> {
                DovecotLiveTestEnvironment.load(
                    environment = invalid,
                    repositoryRoot = repositoryRoot,
                )
            }
        }
    }

    @Test
    fun readinessIsBoundedAndRequiresTheCompleteTopology() {
        val live = DovecotLiveTestEnvironment.load(
            environment = validEnvironment,
            repositoryRoot = repositoryRoot,
        )
        val attempts = AtomicInteger()
        val sleeps = mutableListOf<Long>()
        val observedBoundaries = mutableListOf<DovecotReadinessBoundary>()

        live.awaitReady(
            maxAttempts = 3,
            delayMillis = 7,
            probe = DovecotTopologyReadinessProbe { _, boundary ->
                observedBoundaries += boundary
                boundary != DovecotReadinessBoundary.OAUTH_HEALTH ||
                    attempts.incrementAndGet() == 3
            },
            sleeper = DovecotLiveTestSleeper(sleeps::add),
        )

        assertEquals(3, attempts.get())
        assertEquals(listOf(7L, 7L), sleeps)
        assertEquals(
            DovecotReadinessBoundary.entries.toList().let { boundaries ->
                boundaries + boundaries + boundaries
            },
            observedBoundaries,
        )

        val failedAttempts = AtomicInteger()
        val failure = assertFailsWith<IllegalStateException> {
            live.awaitReady(
                maxAttempts = 2,
                delayMillis = 0,
                probe = DovecotTopologyReadinessProbe { _, boundary ->
                    assertEquals(
                        DovecotReadinessBoundary.ORDINARY_IMAPS,
                        boundary,
                    )
                    failedAttempts.incrementAndGet()
                    false
                },
                sleeper = DovecotLiveTestSleeper {
                    error("zero-delay readiness must not sleep")
                },
            )
        }
        assertEquals(2, failedAttempts.get())
        assertEquals(
            "The fixed Dovecot proof readiness boundary did not become ready: " +
                "ordinary-imaps",
            failure.message,
        )
        assertNull(failure.cause)
    }

    @Test
    fun readinessReportsEachBoundaryInOrderAndPreservesSanitizedCauses() {
        val live = DovecotLiveTestEnvironment.load(
            environment = validEnvironment,
            repositoryRoot = repositoryRoot,
        )
        val boundaries = DovecotReadinessBoundary.entries.toList()

        boundaries.forEachIndexed { failureIndex, failingBoundary ->
            val falseObservations = mutableListOf<DovecotReadinessBoundary>()
            val falseFailure = assertFailsWith<IllegalStateException> {
                live.awaitReady(
                    maxAttempts = 1,
                    delayMillis = 0,
                    probe = DovecotTopologyReadinessProbe { _, boundary ->
                        falseObservations += boundary
                        boundary != failingBoundary
                    },
                )
            }
            assertEquals(
                boundaries.take(failureIndex + 1),
                falseObservations,
            )
            assertEquals(
                "The fixed Dovecot proof readiness boundary did not become " +
                    "ready: ${failingBoundary.diagnosticLabel}",
                falseFailure.message,
            )
            assertNull(falseFailure.cause)

            val sensitiveMarker = "untrusted greeting and secret marker"
            val cause = IOException(sensitiveMarker)
            val exceptionObservations =
                mutableListOf<DovecotReadinessBoundary>()
            val exceptionFailure = assertFailsWith<IllegalStateException> {
                live.awaitReady(
                    maxAttempts = 1,
                    delayMillis = 0,
                    probe = DovecotTopologyReadinessProbe { _, boundary ->
                        exceptionObservations += boundary
                        if (boundary == failingBoundary) {
                            throw cause
                        }
                        true
                    },
                )
            }
            assertEquals(
                boundaries.take(failureIndex + 1),
                exceptionObservations,
            )
            assertEquals(
                "The fixed Dovecot proof readiness boundary did not become " +
                    "ready: ${failingBoundary.diagnosticLabel}",
                exceptionFailure.message,
            )
            assertFalse(
                sensitiveMarker in requireNotNull(exceptionFailure.message),
            )
            assertSame(cause, exceptionFailure.cause)
        }
    }

    @Test
    fun proofComposeOverrideIsExactAndContainsOnlyFixedIsolationChanges() {
        val override = Files.readString(
            repositoryRoot.resolve(
                "debug-dashboard/dashboard-server/testResources/" +
                    "dovecot-gate0c/compose.task5-proof.yml",
            ),
        )

        assertEquals(
            """
            services:
              dovecot:
                ports: !override
                  - "127.0.0.1:1993:31993"
                volumes: !override
                  - ./config:/etc/dovecot/conf.d:ro
                  - type: bind
                    source: ./debug-dashboard/.runtime/task5-proof/dovecot
                    target: /etc/dovecot/runtime
                    read_only: true
                    bind:
                      create_host_path: false
                  - type: bind
                    source: ./debug-dashboard/.runtime/task5-proof/ssl
                    target: /etc/dovecot/ssl
                    read_only: true
                    bind:
                      create_host_path: false
                  - task5-proof-vmail:/srv/vmail
                  - task5-proof-logs:/var/log/dovecot

              dovecot-operator:
                profiles: !override []
                ports: !override
                  - "127.0.0.1:2993:31993"
                volumes: !override
                  - ./config/operator/dovecot.conf:/etc/dovecot/dovecot.conf:ro
                  - type: bind
                    source: ./debug-dashboard/.runtime/task5-proof/dovecot
                    target: /etc/dovecot/runtime
                    read_only: true
                    bind:
                      create_host_path: false
                  - type: bind
                    source: ./debug-dashboard/.runtime/task5-proof/dovecot-operator
                    target: /etc/dovecot/operator-auth
                    read_only: true
                    bind:
                      create_host_path: false
                  - type: bind
                    source: ./debug-dashboard/.runtime/task5-proof/ssl
                    target: /etc/dovecot/ssl
                    read_only: true
                    bind:
                      create_host_path: false
                  - task5-proof-vmail:/srv/vmail

              postfix:
                ports: !override
                  - "127.0.0.1:21025:25"
                volumes: !override
                  - type: bind
                    source: ./debug-dashboard/.runtime/task5-proof/ssl
                    target: /etc/postfix/ssl
                    read_only: true
                    bind:
                      create_host_path: false

              oauth2-mock:
                ports: !override
                  - "127.0.0.1:28080:8080"
                volumes: !override
                  - type: bind
                    source: ./debug-dashboard/.runtime/task5-proof/dovecot
                    target: /etc/dovecot/runtime
                    read_only: true
                    bind:
                      create_host_path: false

              stalwart:
                profiles:
                  - task5-stalwart-disabled

            volumes:
              task5-proof-vmail:
              task5-proof-logs:
            """.trimIndent() + "\n",
            override,
        )
        assertTrue("task5-stalwart-disabled" in override)
        assertTrue("\${" !in override)
    }

    @Test
    fun proofTlsRequiresCanonicalOwnerOnlyCertAndKeyAndReadsCertificateBoundedly() {
        val root = Files.createTempDirectory("dovecot-proof-tls-")
            .toRealPath()
        val dashboard = root.resolve("debug-dashboard")
        val override = root.resolve(
            "debug-dashboard/dashboard-server/testResources/" +
                "dovecot-gate0c/compose.task5-proof.yml",
        )
        val runtime = dashboard.resolve(".runtime")
        val proof = runtime.resolve("task5-proof")
        val ssl = proof.resolve("ssl")
        Files.createDirectories(override.parent)
        Files.createDirectories(ssl)
        Files.writeString(root.resolve("docker-compose.yml"), "services: {}\n")
        Files.writeString(dashboard.resolve("project.yaml"), "modules: []\n")
        Files.writeString(override, "services: {}\n")
        val certificate = ssl.resolve("tls.crt")
        val privateKey = ssl.resolve("tls.key")
        Files.writeString(certificate, "bounded-certificate")
        Files.writeString(privateKey, "private-key")
        Files.setPosixFilePermissions(
            proof,
            PosixFilePermissions.fromString("rwx------"),
        )
        Files.setPosixFilePermissions(
            ssl,
            PosixFilePermissions.fromString("rwx------"),
        )
        Files.setPosixFilePermissions(
            certificate,
            PosixFilePermissions.fromString("rw-------"),
        )
        Files.setPosixFilePermissions(
            privateKey,
            PosixFilePermissions.fromString("rw-------"),
        )
        val profile = DovecotTask5ProofProfile.load(
            environment = validEnvironment,
            repositoryRoot = root,
        )

        profile.requirePreparedTls()
        val bytes = profile.readStableTlsCertificate()
        assertEquals("bounded-certificate", bytes.toString(Charsets.UTF_8))
        bytes.fill(0)

        Files.setPosixFilePermissions(
            privateKey,
            PosixFilePermissions.fromString("rw-r--r--"),
        )
        assertFailsWith<IllegalArgumentException> {
            profile.requirePreparedTls()
        }
        Files.setPosixFilePermissions(
            privateKey,
            PosixFilePermissions.fromString("rw-------"),
        )

        val productionSsl = root.resolve("ssl")
        Files.createDirectory(productionSsl)
        val productionKey = productionSsl.resolve("tls.key")
        Files.move(privateKey, productionKey)
        Files.createLink(privateKey, productionKey)
        assertFailsWith<IllegalArgumentException> {
            profile.requirePreparedTls()
        }
        Files.delete(privateKey)
        Files.move(productionKey, privateKey)

        if (supportsSymbolicLinks()) {
            val realSsl = proof.resolve("real-ssl")
            Files.move(ssl, realSsl)
            Files.createSymbolicLink(ssl, realSsl.fileName)
            assertFailsWith<IllegalArgumentException> {
                profile.requirePreparedTls()
            }
        }
    }

    private fun repositoryRoot(): Path {
        val workingDirectory = Path.of(System.getProperty("user.dir"))
            .toAbsolutePath()
            .normalize()
        val dashboardRoot = if (
            workingDirectory.fileName?.toString() == "dashboard-server"
        ) {
            requireNotNull(workingDirectory.parent)
        } else {
            workingDirectory
        }
        return requireNotNull(dashboardRoot.parent).also { root ->
            require(Files.isRegularFile(root.resolve("docker-compose.yml")))
        }
    }

    private fun supportsSymbolicLinks(): Boolean {
        val root = Files.createTempDirectory("dovecot-proof-symlink-")
        return try {
            val target = Files.createDirectory(root.resolve("target"))
            val link = root.resolve("link")
            Files.createSymbolicLink(link, target.fileName)
            Files.isSymbolicLink(link)
        } catch (_: UnsupportedOperationException) {
            false
        } catch (_: SecurityException) {
            false
        }
    }
}

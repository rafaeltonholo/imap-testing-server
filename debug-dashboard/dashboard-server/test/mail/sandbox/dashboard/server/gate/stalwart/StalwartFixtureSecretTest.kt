package mail.sandbox.dashboard.server.gate.stalwart

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class StalwartFixtureSecretTest {
    private val projectRoot: Path =
        Paths.get(System.getProperty("user.dir")).toAbsolutePath().normalize().let { working ->
            if (working.fileName?.toString() == "dashboard-server") {
                working.parent
            } else {
                working
            }
        }
    private val fixtureRoot: Path =
        projectRoot.resolve("dashboard-server/testResources/stalwart-gate0b")

    @Test
    fun fixtureIsPinnedLoopbackOnlyRecoverySplitAndScratchScoped() {
        StalwartFixtureAudit.validate(
            baseCompose = Files.readString(fixtureRoot.resolve("compose.yml")),
            recoveryCompose = Files.readString(fixtureRoot.resolve("compose.recovery.yml")),
            configJson = Files.readString(fixtureRoot.resolve("config.json")),
        )
    }

    @Test
    fun fixtureExposesOnlyTheReviewedLoopbackHttpAndSmtpProofPorts() {
        val published = fixture().base.lineSequence()
            .map(String::trim)
            .filter { it.startsWith("- \"127.0.0.1:") }
            .toSet()

        assertEquals(
            setOf(
                "- \"127.0.0.1:18443:8080\"",
                "- \"127.0.0.1:18587:8587\"",
            ),
            published,
        )
    }

    @Test
    fun fixtureAuditRejectsEveryUnsafeMutation() {
        val fixture = fixture()
        val mutations = mapOf<String, (FixtureText) -> FixtureText>(
            "moving image tag" to {
                it.copy(
                    base =
                        it.base.replace(
                            "stalwartlabs/stalwart:v0.16.17@sha256:a8108e19bd927e172d4d8c128907b8dfc93fd180ae8ee07dccdd42cb97eb9dfa",
                            "stalwartlabs/stalwart:latest",
                        ),
                )
            },
            "runtime user" to { it.copy(base = it.base.replace("\"2000:2000\"", "\"0:0\"")) },
            "enterprise license" to {
                it.copy(base = it.base + "\n    environment:\n      STALWART_LICENSE_KEY: unsafe\n")
            },
            "external publication" to {
                it.copy(base = it.base.replace("127.0.0.1:18443:8080", "18443:8080"))
            },
            "external smtp publication" to {
                it.copy(base = it.base.replace("127.0.0.1:18587:8587", "18587:8587"))
            },
            "additive external publication" to {
                it.copy(
                    base = it.base.replace(
                        "      - \"127.0.0.1:18443:8080\"",
                        "      - \"127.0.0.1:18443:8080\"\n      - \"18444:8080\"",
                    ),
                )
            },
            "reserved repository port" to {
                it.copy(base = it.base.replace("127.0.0.1:18443:8080", "127.0.0.1:8443:8080"))
            },
            "legacy principal API" to {
                it.copy(base = it.base + "\n# /api/principal\n")
            },
            "additional reviewed-section blank line" to {
                it.copy(
                    base = it.base.replace(
                        "\n\n  stalwart:",
                        "\n\n\n  stalwart:",
                    ),
                )
            },
            "missing base terminal newline" to {
                it.copy(base = it.base.removeSuffix("\n"))
            },
            "additional base terminal newline" to {
                it.copy(base = it.base + "\n")
            },
            "missing recovery terminal newline" to {
                it.copy(recovery = it.recovery.removeSuffix("\n"))
            },
            "impersonation" to {
                it.copy(base = it.base + "\n# impersonate\n")
            },
            "repository Stalwart data" to {
                it.copy(
                    base = it.base.replace(
                        "../../../.runtime/stalwart-gate0b/data",
                        "../../../../stalwart-data",
                    ),
                )
            },
            "additive external mount" to {
                it.copy(
                    base = it.base.replace(
                        "      - ../../../.runtime/stalwart-gate0b/data:/var/lib/stalwart",
                        "      - ../../../.runtime/stalwart-gate0b/data:/var/lib/stalwart\n" +
                            "      - /tmp:/unsafe",
                    ),
                )
            },
            "host network" to {
                it.copy(
                    base = it.base.replace(
                        "    ports:",
                        "    network_mode: host\n    ports:",
                    ),
                )
            },
            "live-only healthcheck" to {
                it.copy(base = it.base.replace("/healthz/ready", "/healthz/live"))
            },
            "commented readiness decoy" to {
                it.copy(
                    base = it.base.replace(
                        "      test: [\"CMD\", \"curl\", \"-fsS\", " +
                            "\"http://127.0.0.1:8080/healthz/ready\"]",
                        "      test: [\"CMD\", \"false\"]\n" +
                            "      # test: [\"CMD\", \"curl\", \"-fsS\", " +
                            "\"http://127.0.0.1:8080/healthz/ready\"]",
                    ),
                )
            },
            "base recovery variable" to {
                it.copy(
                    base = it.base.replace(
                        "STALWART_PUBLIC_URL: http://127.0.0.1:18443",
                        "STALWART_PUBLIC_URL: http://127.0.0.1:18443\n" +
                            "      STALWART_RECOVERY_MODE: \"1\"",
                    ),
                )
            },
            "recovery path leaked into container" to {
                it.copy(
                    recovery = it.recovery.replace(
                        "STALWART_RECOVERY_MODE: \"1\"",
                        "STALWART_RECOVERY_MODE: \"1\"\n" +
                            "      STALWART_GATE_RECOVERY_ENV_FILE: /tmp/leaked",
                    ),
                )
            },
            "missing required host interpolation" to {
                it.copy(
                    recovery = it.recovery.replace(
                        "\${STALWART_GATE_RECOVERY_ENV_FILE:?required}",
                        "./recovery.env",
                    ),
                )
            },
            "additive recovery env file" to {
                it.copy(
                    recovery = it.recovery.replace(
                        "      - \${STALWART_GATE_RECOVERY_ENV_FILE:?required}",
                        "      - \${STALWART_GATE_RECOVERY_ENV_FILE:?required}\n" +
                            "      - /tmp/unsafe.env",
                    ),
                )
            },
            "wrong data store path" to {
                it.copy(config = """{"@type":"RocksDb","path":"/tmp/stalwart/"}""")
            },
        )

        mutations.forEach { (label, mutate) ->
            assertFailsWith<IllegalArgumentException>(label) {
                val candidate = mutate(fixture)
                StalwartFixtureAudit.validate(
                    baseCompose = candidate.base,
                    recoveryCompose = candidate.recovery,
                    configJson = candidate.config,
                )
            }
        }
    }

    @Test
    fun fixtureUsesAProjectScopedInitServiceToHandDataToPinnedUid() {
        val base = fixture().base

        assertTrue(base.contains("  stalwart-data-owner:"))
        assertTrue(base.contains("condition: service_completed_successfully"))
        assertTrue(base.contains("chown 2000:2000 /var/lib/stalwart"))
        assertTrue(base.contains("chmod 0700 /var/lib/stalwart"))
        assertTrue(base.contains("user: \"2000:2000\""))
        assertEquals(
            2,
            base.lineSequence().count {
                it.trim() == "- ./:/etc/stalwart:ro"
            },
        )
        assertEquals(
            2,
            base.lineSequence().count {
                it.trim() ==
                    "- ../../../.runtime/stalwart-gate0b/data:/var/lib/stalwart"
            },
        )
        assertFalse(base.contains("/gate-data"))
        assertFalse(base.contains("./config.json:/etc/stalwart/config.json"))
        assertFalse(base.contains("./config:/etc/stalwart"))
        assertFalse(base.contains("chmod 0777"))
    }

    @Test
    fun resolvedMountAuditAllowsOnlyTheReviewedImageTargetsAndBindSources() {
        withTemporaryProject { temporaryProject ->
            val fixtureDirectory = temporaryProject.resolve("fixture").createDirectories()
            val dataDirectory = temporaryProject.resolve("data").createDirectories()
            val reviewed = listOf(
                StalwartResolvedMount(
                    type = "bind",
                    source = fixtureDirectory.toRealPath(),
                    destination = "/etc/stalwart",
                    readWrite = false,
                ),
                StalwartResolvedMount(
                    type = "bind",
                    source = dataDirectory.toRealPath(),
                    destination = "/var/lib/stalwart",
                    readWrite = true,
                ),
            )

            StalwartDockerMountAudit.validateImageVolumeTargets(
                setOf("/etc/stalwart", "/var/lib/stalwart"),
            )
            StalwartDockerMountAudit.validateResolvedMounts(
                service = "stalwart",
                mounts = reviewed,
                expectedFixtureDirectory = fixtureDirectory,
                expectedDataDirectory = dataDirectory,
            )
            assertEquals(
                reviewed,
                StalwartDockerMountAudit.parseResolvedMounts(
                    reviewed.joinToString(separator = "\n", postfix = "\n") {
                        "${it.type}\t${it.source}\t${it.destination}\t${it.readWrite}"
                    },
                ),
            )

            listOf(
                reviewed + reviewed.first().copy(destination = "/unexpected"),
                reviewed.map {
                    if (it.destination == "/etc/stalwart") it.copy(type = "volume") else it
                },
                reviewed.map {
                    if (it.destination == "/etc/stalwart") it.copy(readWrite = true) else it
                },
                reviewed.map {
                    if (it.destination == "/var/lib/stalwart") {
                        it.copy(source = temporaryProject.resolve("wrong"))
                    } else {
                        it
                    }
                },
            ).forEach { unsafe ->
                assertFailsWith<IllegalArgumentException> {
                    StalwartDockerMountAudit.validateResolvedMounts(
                        service = "stalwart-data-owner",
                        mounts = unsafe,
                        expectedFixtureDirectory = fixtureDirectory,
                        expectedDataDirectory = dataDirectory,
                    )
                }
            }
            assertFailsWith<IllegalArgumentException> {
                StalwartDockerMountAudit.validateImageVolumeTargets(
                    setOf("/etc/stalwart", "/var/lib/stalwart", "/unexpected"),
                )
            }
        }
    }

    @Test
    fun secretHandoffsAreFixedOwnerOnlyAndStrictlyParsed() {
        withTemporaryProject { temporaryProject ->
            val prepared = StalwartGateSecretFiles.prepareRecovery(
                projectRoot = temporaryProject,
                secret = "recovery-only-secret".toCharArray(),
            )

            assertEquals(
                "STALWART_RECOVERY_ADMIN=gate-recovery:recovery-only-secret\n",
                prepared.recoveryEnv.readText(),
            )
            assertEquals(
                setOf("version", "recoveryUsername", "recoverySecret"),
                parseKeys(prepared.recoveryHandoff),
            )
            assertOwnerOnlyDirectory(prepared.runtimeDirectory)
            assertOwnerOnlyDirectory(prepared.dataDirectory)
            assertOwnerOnlyFile(prepared.recoveryEnv)
            assertOwnerOnlyFile(prepared.recoveryHandoff)

            val fixtureSecrets = GateFixtureSecrets(
                managementAccountId = "management-account-id",
                managementApiKey = "API_management-key".toCharArray(),
                firstUserPassword = "first-user-password".toCharArray(),
                secondUserPassword = "second-user-password".toCharArray(),
            )
            StalwartGateSecretFiles.writeFixtureSecrets(
                projectRoot = temporaryProject,
                path = prepared.fixtureSecrets,
                secrets = fixtureSecrets,
            )
            fixtureSecrets.close()

            StalwartGateSecretFiles.readFixtureSecrets(
                projectRoot = temporaryProject,
                environment = mapOf(
                    "STALWART_GATE_FIXTURE_SECRETS_FILE" to
                        prepared.fixtureSecrets.toString(),
                ),
            ).use { loaded ->
                assertEquals("management-account-id", loaded.managementAccountId)
                assertEquals("API_management-key", loaded.managementApiKey.concatToString())
                assertEquals("first-user-password", loaded.firstUserPassword.concatToString())
                assertEquals("second-user-password", loaded.secondUserPassword.concatToString())
            }
            assertOwnerOnlyFile(prepared.fixtureSecrets)

            Files.setPosixFilePermissions(
                prepared.fixtureSecrets,
                PosixFilePermissions.fromString("rw-r--r--"),
            )
            assertFailsWith<IllegalArgumentException> {
                StalwartGateSecretFiles.readFixtureSecrets(
                    projectRoot = temporaryProject,
                    environment = mapOf(
                        "STALWART_GATE_FIXTURE_SECRETS_FILE" to
                            prepared.fixtureSecrets.toString(),
                    ),
                )
            }
        }
    }

    @Test
    fun everySecretReadAndWriteRevalidatesTheFixedRootAndOwnerOnlyAncestor() {
        withTemporaryProject { temporaryProject ->
            val prepared = StalwartGateSecretFiles.prepareRecovery(
                projectRoot = temporaryProject,
                secret = "recovery-only-secret".toCharArray(),
            )
            val fixtureSecrets = fixtureSecrets()
            val lookalikeParent =
                temporaryProject.resolve(".runtime/lookalike/stalwart-gate0b")
            lookalikeParent.createDirectories()
            Files.setPosixFilePermissions(
                lookalikeParent,
                PosixFilePermissions.fromString("rwx------"),
            )

            assertFailsWith<IllegalArgumentException> {
                StalwartGateSecretFiles.writeFixtureSecrets(
                    projectRoot = temporaryProject,
                    path = lookalikeParent.resolve("fixture-secrets"),
                    secrets = fixtureSecrets,
                )
            }

            Files.setPosixFilePermissions(
                prepared.runtimeDirectory,
                PosixFilePermissions.fromString("rwxr-xr-x"),
            )
            assertFailsWith<IllegalArgumentException> {
                StalwartGateSecretFiles.writeFixtureSecrets(
                    projectRoot = temporaryProject,
                    path = prepared.fixtureSecrets,
                    secrets = fixtureSecrets,
                )
            }
            assertFailsWith<IllegalArgumentException> {
                StalwartGateSecretFiles.readRecoveryHandoff(
                    projectRoot = temporaryProject,
                    fixtureSecretsPath = prepared.fixtureSecrets,
                )
            }
            fixtureSecrets.close()
        }

        withTemporaryProject { temporaryProject ->
            val outside = temporaryProject.resolve("outside-runtime")
            outside.createDirectories()
            Files.setPosixFilePermissions(
                outside,
                PosixFilePermissions.fromString("rwx------"),
            )
            val gateRuntime = temporaryProject.resolve(".runtime/stalwart-gate0b")
            Files.createSymbolicLink(gateRuntime, outside)
            val fixtureSecrets = fixtureSecrets()
            assertFailsWith<IllegalArgumentException> {
                StalwartGateSecretFiles.writeFixtureSecrets(
                    projectRoot = temporaryProject,
                    path = gateRuntime.resolve("fixture-secrets"),
                    secrets = fixtureSecrets,
                )
            }
            fixtureSecrets.close()
        }
    }

    @Test
    fun fixtureSecretPathFailsClosedForMissingExternalOrSymlinkedTargets() {
        withTemporaryProject { temporaryProject ->
            val prepared = StalwartGateSecretFiles.prepareRecovery(
                projectRoot = temporaryProject,
                secret = "recovery-only-secret".toCharArray(),
            )

            assertFailsWith<IllegalArgumentException> {
                StalwartGateSecretFiles.fixtureSecretsPath(temporaryProject, emptyMap())
            }
            assertFailsWith<IllegalArgumentException> {
                StalwartGateSecretFiles.fixtureSecretsPath(
                    temporaryProject,
                    mapOf("STALWART_GATE_FIXTURE_SECRETS_FILE" to "/tmp/not-the-gate-file"),
                )
            }

            val outside = temporaryProject.resolve("outside")
            Files.writeString(outside, "outside")
            Files.createSymbolicLink(prepared.fixtureSecrets, outside)
            assertFailsWith<IllegalArgumentException> {
                StalwartGateSecretFiles.readFixtureSecrets(
                    projectRoot = temporaryProject,
                    environment = mapOf(
                        "STALWART_GATE_FIXTURE_SECRETS_FILE" to
                            prepared.fixtureSecrets.toString(),
                    ),
                )
            }
        }
    }

    private fun fixture(): FixtureText = FixtureText(
        base = Files.readString(fixtureRoot.resolve("compose.yml")),
        recovery = Files.readString(fixtureRoot.resolve("compose.recovery.yml")),
        config = Files.readString(fixtureRoot.resolve("config.json")),
    )

    private data class FixtureText(
        val base: String,
        val recovery: String,
        val config: String,
    )

    private fun parseKeys(path: Path): Set<String> =
        path.readText()
            .lineSequence()
            .filter { it.isNotBlank() }
            .map { line -> line.substringBefore('=') }
            .toSet()

    private fun assertOwnerOnlyDirectory(path: Path) {
        assertTrue(Files.isDirectory(path))
        assertEquals(
            "rwx------",
            PosixFilePermissions.toString(Files.getPosixFilePermissions(path)),
        )
    }

    private fun assertOwnerOnlyFile(path: Path) {
        assertTrue(Files.isRegularFile(path))
        assertEquals(
            "rw-------",
            PosixFilePermissions.toString(Files.getPosixFilePermissions(path)),
        )
    }

    private fun fixtureSecrets(): GateFixtureSecrets = GateFixtureSecrets(
        managementAccountId = "management-account-id",
        managementApiKey = "API_management-key".toCharArray(),
        firstUserPassword = "first-user-password".toCharArray(),
        secondUserPassword = "second-user-password".toCharArray(),
    )

    private fun withTemporaryProject(block: (Path) -> Unit) {
        val root = createTempDirectory("stalwart-gate0b-secret-test")
        try {
            root.resolve(".runtime").createDirectories()
            block(root)
        } finally {
            Files.walk(root).use { entries ->
                entries.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }
}

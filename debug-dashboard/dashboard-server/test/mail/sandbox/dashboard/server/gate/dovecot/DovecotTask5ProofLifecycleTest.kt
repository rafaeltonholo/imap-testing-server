package mail.sandbox.dashboard.server.gate.dovecot

import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermissions
import java.time.Duration
import java.util.concurrent.TimeUnit
import kotlin.io.path.createDirectories
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DovecotTask5ProofLifecycleTest {
    private val repositoryRoot = repositoryRoot()
    private val lifecycleScript = repositoryRoot.resolve(
        "debug-dashboard/dashboard-server/testResources/" +
            "dovecot-gate0c/run-task5-proof.sh",
    )
    private val implementationPlan = repositoryRoot.resolve(
        "docs/superpowers/plans/2026-07-23-debug-dashboard-gate-0c-dovecot.md",
    )
    private val gateEvidence = repositoryRoot.resolve(
        "docs/debug-dashboard/gates/0c-dovecot.md",
    )
    private val lifecycleTestSource = repositoryRoot.resolve(
        "debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/" +
            "server/gate/dovecot/DovecotTask5ProofLifecycleTest.kt",
    )
    private val proofProfileSource = repositoryRoot.resolve(
        "debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/" +
            "server/gate/dovecot/DovecotTask5ProofProfile.kt",
    )
    private val networkIsolationHelper = repositoryRoot.resolve(
        "debug-dashboard/dashboard-server/testResources/" +
            "dovecot-gate0c/network-isolation-check.py",
    )
    private val operatorConfigTestSource = repositoryRoot.resolve(
        "debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/" +
            "server/gate/dovecot/DovecotOperatorConfigTest.kt",
    )

    @Test
    fun operatorConfigAuditConsumesOnlyLifecycleOwnedEvidence() {
        val source = Files.readString(operatorConfigTestSource)

        listOf(
            "runBoundedProcess(",
            "ProcessBuilder(command)",
            "command = listOf(\"docker\"",
            "COMPOSE_TIMEOUT",
        ).forEach { forbidden ->
            assertFalse(forbidden in source, forbidden)
        }
        listOf(
            "base-compose.json",
            "proof-compose.json",
            "ordinary-doveconf.txt",
            "operator-doveconf.txt",
            "TASK5_DOVECOT_EVIDENCE_ROOT",
        ).forEach { evidenceContract ->
            assertTrue(evidenceContract in source, evidenceContract)
        }
    }

    @Test
    fun lifecycleScriptHasValidBashSyntaxAndFailClosedStaticContract() {
        assertTrue(Files.isRegularFile(lifecycleScript))
        assertTrue(Files.isExecutable(lifecycleScript))

        val syntax = runProcess(
            command = listOf("/bin/bash", "-n", lifecycleScript.toString()),
            workingDirectory = repositoryRoot,
        )
        assertEquals(0, syntax.exitCode, syntax.output)
        val nonPrivilegedInvocation = runProcess(
            command = listOf("/bin/bash", lifecycleScript.toString()),
            workingDirectory = repositoryRoot,
        )
        assertTrue(
            nonPrivilegedInvocation.exitCode != 0,
            nonPrivilegedInvocation.output,
        )

        val source = Files.readString(lifecycleScript)
        assertTrue(
            source.startsWith(
                "#!/bin/bash -p\n\n",
            ),
        )
        assertTrue("""if [[ "$-" != *p* ]]; then""" in source)
        assertTrue("/usr/bin/env -i" in source)
        assertTrue("/usr/bin/env -0" in source)
        assertTrue(
            "/bin/bash --noprofile --norc -p \"\$0\"" in source,
        )
        assertEquals(
            1,
            source.windowed(PRODUCTION_TRUSTED_PATH.length).count {
                it == PRODUCTION_TRUSTED_PATH
            },
            "The lifecycle must define one fixed trusted PATH literal",
        )
        val importedCollisionReset = source.indexOf(
            "unset TASK5_LIFECYCLE_LOCK_TOKEN " +
                "TASK5_PROOF_ROOT_TOKEN token actual_token",
        )
        val lockTokenInitialization = source.indexOf(
            "TASK5_LIFECYCLE_LOCK_TOKEN=\"\"",
        )
        val rootTokenInitialization = source.indexOf(
            "TASK5_PROOF_ROOT_TOKEN=\"\"",
        )
        val globalTokenDeExport = source.indexOf(
            "export -n TASK5_LIFECYCLE_LOCK_TOKEN " +
                "TASK5_PROOF_ROOT_TOKEN",
        )
        val shellOptionsDeExport = source.indexOf("export -n SHELLOPTS")
        assertTrue(importedCollisionReset > source.indexOf("set -euo pipefail"))
        assertTrue(lockTokenInitialization > importedCollisionReset)
        assertTrue(rootTokenInitialization > lockTokenInitialization)
        assertTrue(globalTokenDeExport > rootTokenInitialization)
        assertTrue(shellOptionsDeExport > globalTokenDeExport)
        assertEquals(
            source.lineSequence().count {
                it.trim() == "local token" ||
                    it.trim().startsWith("local token=")
            },
            source.lineSequence().count { it.trim() == "export -n token" },
        )
        assertEquals(
            source.lineSequence().count { it.trim() == "local actual_token" },
            source.lineSequence().count {
                it.trim() == "export -n actual_token"
            },
        )
        assertTrue("trap 'task5_on_exit \$?' EXIT" in source)
        assertTrue("trap 'task5_record_signal 130' INT" in source)
        assertTrue("trap 'task5_record_signal 143' TERM" in source)
        assertFalse("trap 'exit 130' INT" in source)
        assertFalse("trap 'exit 143' TERM" in source)
        assertFalse("trap - EXIT INT TERM" in source)
        assertTrue(
            source.indexOf("TASK5_CLEANUP_IN_PROGRESS=1") <
                source.indexOf("trap - EXIT"),
        )
        assertTrue(
            "{{with (index .State \"Health\")}}{{.Status}}" +
                "{{else}}none{{end}}" in source,
        )
        assertFalse(".State.Health" in source)
        assertFalse("stalwart" in source.lowercase())
        assertFalse(Regex("""compose(?: \\\n)?\s+up\s*(?:\\\n)?\s*$""").containsMatchIn(source))
        assertFalse("docker context" in source.lowercase())
        assertFalse("unset DOCKER_HOST" in source)
        assertEquals(
            1,
            source.windowed(PRODUCTION_LIFECYCLE_LOCK.length).count {
                it == PRODUCTION_LIFECYCLE_LOCK
            },
            "The daemon-global lifecycle lock must be one fixed literal",
        )
        assertTrue(
            "readonly TASK5_LIFECYCLE_LOCK=" +
                "\"$PRODUCTION_LIFECYCLE_LOCK\"" in source,
        )
        assertTrue(
            "task5_directory_is_exact_physical " +
                "\"\$TASK5_LIFECYCLE_LOCK_PARENT\"" in source,
        )
        assertFalse("TASK5_LIFECYCLE_LOCK_OVERRIDE" in source)
        assertFalse("TASK5_FAKE_" in source)
        assertFalse("export TASK5_LIFECYCLE_LOCK_TOKEN" in source)
        assertTrue(
            "TASK5_NETWORK_ISOLATION_HELPER=" +
                "\"\$TASK5_SCRIPT_DIRECTORY/network-isolation-check.py\"" in source,
        )
        assertTrue(
            "[[ ! -f \"\$TASK5_NETWORK_ISOLATION_HELPER\" ]]" in source,
        )
        assertTrue(
            "[[ -L \"\$TASK5_NETWORK_ISOLATION_HELPER\" ]]" in source,
        )
        assertTrue(Files.isRegularFile(networkIsolationHelper))
        assertFalse(Files.isSymbolicLink(networkIsolationHelper))

        val ambientOverrideRejection = source.indexOf(
            "DOVECOT_* | COMPOSE_* | DOCKER_*",
        )
        val fixedDockerHost = source.indexOf(
            "export DOCKER_HOST=unix:///var/run/docker.sock",
        )
        val exitTrap = source.indexOf("trap 'task5_on_exit \$?' EXIT")
        val lockAcquisition = source.lastIndexOf(
            "\ntask5_acquire_lifecycle_lock\n",
        )
        val initialInventory = source.lastIndexOf(
            "\ntask5_inventory_is_empty \"initial\"\n",
        )
        assertTrue(ambientOverrideRejection >= 0)
        assertTrue(fixedDockerHost > ambientOverrideRejection)
        assertEquals(
            1,
            source.windowed(
                "export DOCKER_HOST=unix:///var/run/docker.sock".length,
            ).count {
                it == "export DOCKER_HOST=unix:///var/run/docker.sock"
            },
        )
        assertTrue(exitTrap > fixedDockerHost)
        assertTrue(lockAcquisition > exitTrap)
        assertTrue(initialInventory > lockAcquisition)
        assertFalse(
            "install -d -m 700 \"\$TASK5_PROOF_ROOT\"" in source,
        )
        assertTrue(
            "task5_require_lifecycle_lock_ownership " +
                "\"Docker Compose \$1\" || return 1" in source,
        )
        listOf(
            "task5_path_identity",
            "task5_path_mode",
            "task5_path_size",
        ).forEach { function ->
            assertTrue(
                "$function() {\n  trap '' INT TERM\n  stat " in source,
                "$function must shield its command-substitution shell",
            )
            assertFalse("$function() {\n  (" in source)
        }
        assertTrue("if set -m; then" in source)
        assertTrue(
            "could not enable cleanup process-group isolation" in source,
        )

        val profileSource = Files.readString(proofProfileSource)
        assertTrue(
            "environment[DOCKER_HOST_KEY] == FIXED_DOCKER_HOST" in
                profileSource,
        )
        assertTrue(
            "private const val DOCKER_HOST_KEY = \"DOCKER_HOST\"" in
                profileSource &&
                "\"unix:///var/run/docker.sock\"" in
                profileSource,
        )

        val staticConfigTest = source.indexOf(
            "--include-classes " +
                "mail.sandbox.dashboard.server.gate.dovecot." +
                "DovecotOperatorConfigTest",
        )
        val credentialStoreTest = source.indexOf(
            "--include-classes " +
                "mail.sandbox.dashboard.server.gate.dovecot." +
                "DovecotOperatorCredentialStoreTest",
        )
        val baseComposeConfig = source.indexOf(
            "COMPOSE_DISABLE_ENV_FILE=1 " +
                "docker compose --file docker-compose.yml \\\n" +
                "  config --quiet oauth2-mock dovecot postfix",
        )
        val proofComposeConfig = source.indexOf(
            "COMPOSE_DISABLE_ENV_FILE=1 task5_compose \\\n" +
                "  config --quiet oauth2-mock dovecot postfix " +
                "dovecot-operator",
        )
        listOf(
            "DovecotAuthenticationResponseClassifierTest",
            "DovecotIsolationMailboxContractTest",
        ).forEach { className ->
            assertTrue(
                "--include-classes " +
                    "mail.sandbox.dashboard.server.gate.dovecot.$className" in source,
                className,
            )
        }
        assertTrue(staticConfigTest >= 0)
        assertTrue(credentialStoreTest > staticConfigTest)
        assertTrue(baseComposeConfig > credentialStoreTest)
        assertTrue(proofComposeConfig > baseComposeConfig)

        var previousBoundary = proofComposeConfig
        listOf(
            "export DOVECOT_LIVE_TESTS=1",
            "export DOVECOT_LIVE_PROFILE=task5-proof",
            "export COMPOSE_PROJECT_NAME=mail-sandbox-task5-proof",
            "export COMPOSE_FILE=\"docker-compose.yml:" +
                "\$TASK5_PROOF_COMPOSE_RELATIVE\"",
            "export COMPOSE_DISABLE_ENV_FILE=1",
        ).forEach { export ->
            val exportIndex = source.indexOf(export)
            assertTrue(exportIndex > previousBoundary)
            previousBoundary = exportIndex
        }

        val proofRootCreation = source.lastIndexOf(
            "\ntask5_create_owned_proof_root\n",
        )
        listOf(
            "readonly TASK5_PROVIDER_EVIDENCE_ROOT=\"\$TASK5_PROOF_ROOT/provider-evidence\"",
            "readonly TASK5_BASE_COMPOSE_EVIDENCE=\"\$TASK5_PROVIDER_EVIDENCE_ROOT/base-compose.json\"",
            "readonly TASK5_PROOF_COMPOSE_EVIDENCE=\"\$TASK5_PROVIDER_EVIDENCE_ROOT/proof-compose.json\"",
            "readonly TASK5_ORDINARY_DOVECONF_EVIDENCE=\"\$TASK5_PROVIDER_EVIDENCE_ROOT/ordinary-doveconf.txt\"",
            "readonly TASK5_OPERATOR_DOVECONF_EVIDENCE=\"\$TASK5_PROVIDER_EVIDENCE_ROOT/operator-doveconf.txt\"",
            "mkdir \\\n      \"\$TASK5_PROOF_ROOT/dovecot\" \\\n      \"\$TASK5_PROVIDER_EVIDENCE_ROOT\" \\\n      \"\$TASK5_PROOF_ROOT/ssl\"",
            "task5_require_mode \"\$TASK5_PROVIDER_EVIDENCE_ROOT\" 700",
        ).forEach { contract ->
            assertTrue(contract in source, contract)
        }
        val baseComposeEvidence = source.indexOf(
            "task5_capture_provider_evidence \\\n" +
                "  \"base service-scoped Compose model\" \\\n" +
                "  \"\$TASK5_BASE_COMPOSE_EVIDENCE\" \\\n" +
                "  /usr/bin/env -u COMPOSE_FILE -u COMPOSE_PROJECT_NAME \\\n" +
                "    docker compose --file docker-compose.yml \\\n" +
                "      --profile dovecot-operator config --format json \\\n" +
                "      oauth2-mock dovecot postfix dovecot-operator",
        )
        val proofComposeEvidence = source.indexOf(
            "task5_capture_provider_evidence \\\n" +
                "  \"proof service-scoped Compose model\" \\\n" +
                "  \"\$TASK5_PROOF_COMPOSE_EVIDENCE\" \\\n" +
                "  task5_compose_with_lock config --format json \\\n" +
                "    oauth2-mock dovecot postfix dovecot-operator",
        )
        val certificateRequest = source.indexOf(
            "openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \\\n" +
                "    -subj /CN=localhost \\\n" +
                "    -addext subjectAltName=DNS:localhost \\\n" +
                "    -keyout \"\$TASK5_PROOF_ROOT/ssl/tls.key\" \\\n" +
                "    -out \"\$TASK5_PROOF_ROOT/ssl/tls.crt\"",
        )
        val certificateRegularFileValidation = source.indexOf(
            "TLS material is not fixed regular-file input",
        )
        val certificateKeyModeValidation = source.indexOf(
            "task5_require_mode \"\$TASK5_PROOF_ROOT/ssl/tls.key\" 600",
        )
        val certificateVerification = source.indexOf(
            "openssl verify " +
                "-CAfile \"\$TASK5_PROOF_ROOT/ssl/tls.crt\" " +
                "-verify_hostname localhost " +
                "\"\$TASK5_PROOF_ROOT/ssl/tls.crt\"",
        )
        val proofPreflight = source.indexOf("-- task5-proof preflight")
        assertTrue(proofRootCreation > previousBoundary)
        assertTrue(baseComposeEvidence > proofRootCreation)
        assertTrue(proofComposeEvidence > baseComposeEvidence)
        assertTrue(certificateRequest > proofComposeEvidence)
        assertTrue(certificateRegularFileValidation > certificateRequest)
        assertTrue(certificateKeyModeValidation > certificateRegularFileValidation)
        assertTrue(certificateVerification > certificateKeyModeValidation)
        assertTrue(proofPreflight > proofRootCreation)
        assertTrue(proofPreflight > certificateVerification)

        val evidenceFunctionStart = source.indexOf(
            "task5_capture_provider_evidence() {",
        )
        val evidenceFunctionEnd = source.indexOf(
            "\ntask5_record_cleanup_failure() {",
            startIndex = evidenceFunctionStart,
        )
        assertTrue(evidenceFunctionStart >= 0)
        assertTrue(evidenceFunctionEnd > evidenceFunctionStart)
        val evidenceFunction = source.substring(
            evidenceFunctionStart,
            evidenceFunctionEnd,
        )
        listOf(
            "\$TASK5_BASE_COMPOSE_EVIDENCE",
            "\$TASK5_PROOF_COMPOSE_EVIDENCE",
            "\$TASK5_ORDINARY_DOVECONF_EVIDENCE",
            "\$TASK5_OPERATOR_DOVECONF_EVIDENCE",
            "task5_directory_is_exact_physical \"\$TASK5_PROVIDER_EVIDENCE_ROOT\"",
            "task5_path_mode \"\$TASK5_PROVIDER_EVIDENCE_ROOT\"",
            "set -o noclobber",
            "\"\$@\" > \"\$path\"",
            "[[ ! -f \"\$path\" ]]",
            "[[ -L \"\$path\" ]]",
            "task5_require_mode \"\$path\" 600",
            "size < 1 || size > 1048576",
        ).forEach { contract ->
            assertTrue(contract in evidenceFunction, contract)
        }

        val proofPortLoop = assertNotNull(
            Regex("""for TASK5_PROOF_PORT in ([0-9 ]+); do""")
                .find(source),
            "The lifecycle must reserve one fixed proof-port set",
        ).groupValues[1].trim().split(Regex("""\s+"""))
        assertEquals(
            listOf("1993", "21995", "2993", "21025", "28080"),
            proofPortLoop,
        )
        assertEquals(
            1,
            source.windowed("2993".length).count { it == "2993" },
            "Port 2993 is reserved only by the fixed negative lsof probe",
        )

        val startupTest = source.indexOf(
            "--include-classes " +
                "mail.sandbox.dashboard.server.gate.dovecot." +
                "DovecotOperatorStartupLiveTest",
        )
        val isolationTest = source.indexOf(
            "--include-classes " +
                "mail.sandbox.dashboard.server.gate.dovecot." +
                "DovecotIsolationLiveTest",
        )
        val rotationTest = source.indexOf(
            "--include-classes " +
                "mail.sandbox.dashboard.server.gate.dovecot." +
                "DovecotOperatorRotationLiveTest",
        )
        val completion = source.indexOf(
            """printf '%s\n' "Task 5 proof completed; mandatory cleanup follows."""",
        )
        assertTrue(startupTest > proofPreflight)
        assertTrue(isolationTest > startupTest)
        assertTrue(rotationTest > isolationTest)
        assertTrue(completion > rotationTest)
    }

    @Test
    fun lifecycleProvesExactDisposableProviderVersionsAndRuntimeConfigs() {
        val source = Files.readString(lifecycleScript)
        val normalizedSource = source
            .replace(Regex("""\\\r?\n"""), " ")
            .replace(Regex("""\s+"""), " ")
        val packageFormat = "'-f=${'$'}{Package}=${'$'}{Version}\\n'"
        val expectedChecks = listOf(
            "task5_require_exact_output \"dovecot --version\" " +
                "\"2.4.4 (8b687aa65c)\" task5_compose_with_lock exec -T " +
                "dovecot dovecot --version",
            "task5_require_exact_output \"python --version\" \"Python 3.14.6\" " +
                "task5_compose_with_lock exec -T oauth2-mock python --version",
            "task5_require_exact_output \"postconf mail_version\" \"3.10.12\" " +
                "task5_compose_with_lock exec -T postfix postconf -h mail_version",
            "task5_require_exact_output \"postconf compatibility_level\" \"3.6\" " +
                "task5_compose_with_lock exec -T postfix postconf -h " +
                "compatibility_level",
            "task5_require_exact_output \"dpkg-query postfix\" " +
                "\"postfix=3.10.12-0+deb13u2\" task5_compose_with_lock " +
                "exec -T postfix dpkg-query -W $packageFormat postfix",
            "task5_require_exact_output \"dpkg-query libsasl2-2\" " +
                "\"libsasl2-2=2.1.28+dfsg1-9\" task5_compose_with_lock " +
                "exec -T postfix dpkg-query -W $packageFormat libsasl2-2",
            "task5_require_exact_output \"dpkg-query libsasl2-modules\" " +
                "\"libsasl2-modules=2.1.28+dfsg1-9\" task5_compose_with_lock " +
                "exec -T postfix dpkg-query -W $packageFormat libsasl2-modules",
            "task5_require_exact_output \"dpkg-query sasl2-bin\" " +
                "\"sasl2-bin=2.1.28+dfsg1-9\" task5_compose_with_lock " +
                "exec -T postfix dpkg-query -W $packageFormat sasl2-bin",
            "task5_require_exact_output \"dpkg-query netcat-openbsd\" " +
                "\"netcat-openbsd=1.229-1\" task5_compose_with_lock " +
                "exec -T postfix dpkg-query -W $packageFormat netcat-openbsd",
            "task5_capture_provider_evidence \"ordinary doveconf -n\" " +
                "\"\$TASK5_ORDINARY_DOVECONF_EVIDENCE\" " +
                "task5_compose_with_lock exec -T dovecot " +
                "/dovecot/bin/doveconf -n",
            "task5_capture_provider_evidence \"operator doveconf -n\" " +
                "\"\$TASK5_OPERATOR_DOVECONF_EVIDENCE\" " +
                "task5_compose_with_lock exec -T dovecot-operator " +
                "/dovecot/bin/doveconf -n",
            "task5_require_success \"operator healthcheck\" " +
                "task5_compose_with_lock exec -T dovecot-operator " +
                "/usr/local/bin/operator-healthcheck",
        )

        expectedChecks.forEach { expected ->
            assertTrue(expected in normalizedSource, "missing live proof: $expected")
        }

        val operatorStart = normalizedSource.indexOf(
            "up --detach --build --force-recreate --no-deps --wait " +
                "dovecot-operator",
        )
        val versionProof = normalizedSource.lastIndexOf(
            "task5_require_exact_output \"dovecot --version\"",
        )
        val ordinaryConfigEvidence = normalizedSource.indexOf(
            "task5_capture_provider_evidence \"ordinary doveconf -n\"",
        )
        val operatorConfigEvidence = normalizedSource.indexOf(
            "task5_capture_provider_evidence \"operator doveconf -n\"",
        )
        val ownedEvidenceAudit = normalizedSource.indexOf(
            "DovecotOperatorOwnedEvidenceLiveTest",
        )
        val ownedEvidenceEnvironment = normalizedSource.indexOf(
            "TASK5_DOVECOT_EVIDENCE_ROOT=\"\$TASK5_PROVIDER_EVIDENCE_ROOT\"",
        )
        val healthcheck = normalizedSource.indexOf(
            "task5_require_success \"operator healthcheck\"",
        )
        val startupLive = normalizedSource.indexOf(
            "DovecotOperatorStartupLiveTest",
        )
        assertTrue(operatorStart >= 0)
        assertTrue(versionProof > operatorStart)
        assertTrue(ordinaryConfigEvidence > versionProof)
        assertTrue(operatorConfigEvidence > ordinaryConfigEvidence)
        assertTrue(ownedEvidenceEnvironment > operatorConfigEvidence)
        assertTrue(ownedEvidenceAudit > operatorConfigEvidence)
        assertTrue(ownedEvidenceAudit > ownedEvidenceEnvironment)
        assertTrue(healthcheck > ownedEvidenceAudit)
        assertTrue(startupLive > healthcheck)
    }

    @Test
    fun lifecycleRejectsMismatchedProviderVersionAndRunsCheckedCleanup() {
        withFixture { fixture ->
            val result = fixture.run("provider-version-mismatch")

            assertTrue(result.exitCode != 0, result.output)
            assertTrue(
                "Task 5 proof: dovecot --version returned an unexpected value" in
                    result.output,
                result.output,
            )
            assertFalse(
                result.commands.any {
                    "DovecotOperatorStartupLiveTest" in it
                },
                "live operations must not run after a version mismatch",
            )
            assertCleanupInventoriesAndBaselineAfterDown(result.commands)
            assertFalse(Files.exists(fixture.proofRoot))
            assertFalse(
                Files.exists(
                    fixture.lifecycleLock,
                    LinkOption.NOFOLLOW_LINKS,
                ),
            )
        }
    }

    @Test
    fun lifecycleDockerInventoryIsExactAndOrdinaryBaselineIsAllowlisted() {
        val source = Files.readString(lifecycleScript)
        val logicalSource = source.replace(Regex("""\\\r?\n"""), " ")
        val normalizedSource = logicalSource.replace(Regex("""\s+"""), " ")
        val violations = buildList {
            listOf(
                "all-container name inventory" to Regex(
                    """^\s*docker\s+ps\s+--all\s+--format\s+['\"]?\{\{\.Names}}['\"]?\s*$""",
                    setOf(RegexOption.IGNORE_CASE, RegexOption.MULTILINE),
                ),
                "all-network name inventory" to Regex(
                    """^\s*docker\s+network\s+ls\s+--format\s+['\"]?\{\{\.Name}}['\"]?\s*$""",
                    setOf(RegexOption.IGNORE_CASE, RegexOption.MULTILINE),
                ),
                "all-volume name inventory" to Regex(
                    """^\s*docker\s+volume\s+ls\s+--format\s+['\"]?\{\{\.Name}}['\"]?\s*$""",
                    setOf(RegexOption.IGNORE_CASE, RegexOption.MULTILINE),
                ),
                "unfiltered running-container baseline" to Regex(
                    """^\s*if\s+docker\s+ps\s+--quiet\s*>""",
                    setOf(RegexOption.IGNORE_CASE, RegexOption.MULTILINE),
                ),
                "unscoped base Compose config" to Regex(
                    """^\s*COMPOSE_DISABLE_ENV_FILE=1\s+docker\s+compose\b[^\n]*config\s+--quiet\s*$""",
                    setOf(RegexOption.IGNORE_CASE, RegexOption.MULTILINE),
                ),
                "unscoped proof Compose config" to Regex(
                    """^\s*COMPOSE_DISABLE_ENV_FILE=1\s+task5_compose\s+config\s+--quiet\s*$""",
                    setOf(RegexOption.IGNORE_CASE, RegexOption.MULTILINE),
                ),
            ).forEach { (description, forbidden) ->
                if (forbidden.containsMatchIn(logicalSource)) {
                    add("broad Docker access: $description")
                }
            }
            if (
                "TASK5_BASELINE_PROJECT_FILTER=\"label=com.docker.compose.project=" +
                "dovecot-docker\"" !in source
            ) {
                add("missing exact ordinary-project baseline filter")
            }
            val serviceAllowlist = Regex(
                """TASK5_BASELINE_SERVICES=\(\s*dovecot\s+postfix\s+oauth2-mock\s*\)""",
            ).find(source)
            if (serviceAllowlist == null) {
                add("missing exact dovecot/postfix/oauth2-mock baseline allowlist")
            }
            if (
                "--filter \"\$TASK5_BASELINE_PROJECT_FILTER\"" !in source ||
                "--filter \"label=com.docker.compose.service=" !in source
            ) {
                add("baseline IDs are not selected by project plus service labels")
            }
            if ("task5_capture_allowlisted_baseline_ids" !in source) {
                add("baseline and postflight do not share an allowlisted ID capture")
            }
            if (
                "docker compose --file docker-compose.yml config --quiet " +
                "oauth2-mock dovecot postfix" !in normalizedSource
            ) {
                add("base Compose config can resolve a non-allowlisted service")
            }
            if (
                "task5_compose config --quiet oauth2-mock dovecot postfix " +
                "dovecot-operator" !in normalizedSource
            ) {
                add("proof Compose config can resolve a non-proof service")
            }
            if (
                "docker compose --file docker-compose.yml --profile " +
                "dovecot-operator config --format json oauth2-mock dovecot " +
                "postfix dovecot-operator" !in normalizedSource
            ) {
                add("base Compose evidence can resolve a non-allowlisted service")
            }
            if (
                "task5_compose_with_lock config --format json oauth2-mock " +
                "dovecot postfix dovecot-operator" !in normalizedSource
            ) {
                add("proof Compose evidence can resolve a non-proof service")
            }
        }

        assertEquals(
            emptyList(),
            violations,
            violations.joinToString(separator = "\n"),
        )
    }

    @Test
    fun strictFakeDockerRejectsAnyNonAllowlistedInventoryOrInspectPath() {
        withFixture { fixture ->
            val result = fixture.run(scenario = "success")

            assertEquals(0, result.exitCode, result.output)
            assertFalse(
                result.commands.any { it.startsWith("forbidden-docker-access ") },
                result.commands.joinToString("\n"),
            )
        }
    }

    @Test
    fun strictFakeDockerRejectsMultiTargetInspectAndUnscopedDown() {
        withFixture { fixture ->
            val allowedId = "1".repeat(64)
            val arbitraryId = "f".repeat(64)
            val inspect = fixture.runFakeDocker(
                listOf(
                    "inspect",
                    "--format",
                    HEALTH_INSPECT_FORMAT,
                    arbitraryId,
                    allowedId,
                ),
            )
            val unscopedDown = fixture.runFakeDocker(
                listOf("compose", "down", "--volumes", "--remove-orphans"),
            )

            assertEquals(88, inspect.exitCode, inspect.output)
            assertEquals(88, unscopedDown.exitCode, unscopedDown.output)
        }
    }

    @Test
    fun processHelpersRedirectOutputBeforeBoundedWaitAndRead() {
        val source = Files.readString(lifecycleTestSource)
        val forbiddenPreWaitRead = "process.inputStream." + "readAllBytes()"
        val redirectToken = ".redirect" + "Output("
        val waitToken = "process." + "waitFor("
        val postWaitReadToken = "Files.readString(" + "outputFile)"

        assertFalse(forbiddenPreWaitRead in source)
        assertTrue(
            source.windowed(redirectToken.length)
                .count { it == redirectToken } >= 2,
        )
        assertTrue(
            source.windowed(waitToken.length)
                .count { it == waitToken } >= 2,
        )
        assertTrue(
            source.windowed(postWaitReadToken.length)
                .count { it == postWaitReadToken } >= 2,
        )
    }

    @Test
    fun failedInitialDockerResourceQueryHaltsBeforeMutation() {
        withFixture { fixture ->
            val result = fixture.run("initial-network-query-fails")

            assertTrue(result.exitCode != 0, result.output)
            assertTrue(result.commands.any { it.startsWith("docker network ls ") })
            assertNoProofMutation(result.commands)
            assertNoPreflightExecution(result.commands)
            assertFalse(Files.exists(fixture.proofRoot))
        }
    }

    @Test
    fun successfulNonemptyLabeledInventoryHaltsBeforeMutation() {
        withFixture { fixture ->
            val result = fixture.run("labeled-resource-collision")

            assertTrue(result.exitCode != 0, result.output)
            assertNoProofMutation(result.commands)
            assertNoPreflightExecution(result.commands)
            assertFalse(Files.exists(fixture.proofRoot))
        }
    }

    @Test
    fun everyUnlabeledExactFixedNameCollisionHaltsBeforeMutation() {
        FIXED_PROOF_RESOURCE_NAMES.forEach { exactName ->
            withFixture { fixture ->
                val result = fixture.run(
                    scenario = "exact-name-collision",
                    extraEnvironment = mapOf(
                        "TASK5_FAKE_COLLISION_NAME" to exactName,
                    ),
                )

                assertTrue(
                    result.exitCode != 0,
                    "$exactName unexpectedly passed:\n${result.output}",
                )
                assertTrue(
                    result.commands.any { it == "fake-name-output $exactName" },
                    result.commands.joinToString("\n"),
                )
                assertNoProofMutation(result.commands)
                assertNoPreflightExecution(result.commands)
                assertFalse(Files.exists(fixture.proofRoot))
            }
        }
    }

    @Test
    fun everyFullNameInventoryQueryFailureHaltsBeforeMutation() {
        listOf(
            "full-container-query-fails",
            "full-network-query-fails",
            "full-volume-query-fails",
        ).forEach { scenario ->
            withFixture { fixture ->
                val result = fixture.run(scenario)

                assertTrue(result.exitCode != 0, "$scenario: ${result.output}")
                assertNoProofMutation(result.commands)
                assertNoPreflightExecution(result.commands)
                assertFalse(Files.exists(fixture.proofRoot))
            }
        }
    }

    @Test
    fun portCollisionAndPortQueryFailureBothHaltBeforeMutation() {
        listOf("port-collision", "port-query-fails").forEach { scenario ->
            withFixture { fixture ->
                val result = fixture.run(scenario)

                assertTrue(result.exitCode != 0, "$scenario: ${result.output}")
                assertTrue(result.commands.any { it.startsWith("lsof ") })
                assertNoProofMutation(result.commands)
                assertNoPreflightExecution(result.commands)
                assertFalse(Files.exists(fixture.proofRoot))
            }
        }
    }

    @Test
    fun failedBaselineListOrInspectPreventsBaselineReadyAndProofRootCreation() {
        listOf("baseline-ps-fails", "baseline-inspect-fails").forEach { scenario ->
            withFixture { fixture ->
                val result = fixture.run(scenario)

                assertTrue(result.exitCode != 0, "$scenario: ${result.output}")
                assertFalse(Files.exists(fixture.proofRoot))
                assertNoProofMutation(result.commands)
                assertNoPreflightExecution(result.commands)
                assertFalse(
                    result.commands.any { it.startsWith("lsof ") },
                    "Port checks must not run until the complete baseline is ready",
                )
            }
        }
    }

    @Test
    fun postflightBaselineDivergenceRetainsEvidenceAndLifecycleLock() {
        listOf(
            "postflight-id-changes" to
                "allowlisted ordinary-service container inventory changed",
            "postflight-state-changes" to
                "an allowlisted pre-existing container changed",
            "postflight-list-fails" to
                "could not recapture allowlisted ordinary-service containers",
            "postflight-inspect-fails" to
                "could not inspect an allowlisted baseline container",
        ).forEach { (scenario, expectedFailure) ->
            withFixture { fixture ->
                val result = fixture.run(scenario)

                assertTrue(result.exitCode != 0, "$scenario: ${result.output}")
                assertTrue(expectedFailure in result.output, result.output)
                assertFalse("baseline-match" in result.output, result.output)
                assertTrue("baseline evidence retained at " in result.output)
                assertTrue(fixture.hasBaselineDirectory())
                assertTrue(
                    Files.isDirectory(
                        fixture.lifecycleLock,
                        LinkOption.NOFOLLOW_LINKS,
                    ),
                    "$scenario must retain the lifecycle lock with evidence",
                )
                assertCleanupInventoriesAndBaselineAfterDown(result.commands)
                assertFalse(Files.exists(fixture.proofRoot))
            }
        }
    }

    @Test
    fun mainFailureRunsCompleteCleanupAndPreservesPrimaryStatus() {
        withFixture { fixture ->
            val result = fixture.run("main-live-fails")

            assertEquals(23, result.exitCode, result.output)
            assertOrdered(
                result.commands,
                "kotlin test --include-module dashboard-server " +
                    "--include-classes " +
                    "mail.sandbox.dashboard.server.gate.dovecot." +
                    "DovecotOperatorStartupLiveTest",
                "kotlin run --module dashboard-server --main-class " +
                    "mail.sandbox.dashboard.server.gate.dovecot." +
                    "EligibilityFileCli -- task5-proof remove " +
                    "task5-bootstrap@local.test",
                "docker compose --project-name mail-sandbox-task5-proof " +
                    "--file docker-compose.yml --file " +
                    "debug-dashboard/dashboard-server/testResources/" +
                    "dovecot-gate0c/compose.task5-proof.yml down " +
                    "--volumes --remove-orphans",
            )
            assertCleanupInventoriesAndBaselineAfterDown(result.commands)
            assertFalse(Files.exists(fixture.proofRoot))
        }
    }

    @Test
    fun cleanupFailureCannotTurnMainSuccessOrFailureIntoExitZero() {
        withFixture { fixture ->
            val result = fixture.run("bootstrap-remove-fails")
            assertTrue(result.exitCode != 0, result.output)
            assertCleanupInventoriesAndBaselineAfterDown(result.commands)
        }
        withFixture { fixture ->
            val result = fixture.run("main-and-down-fail")
            assertEquals(23, result.exitCode, result.output)
            assertCleanupInventoriesAndBaselineAfterDown(result.commands)
        }
    }

    @Test
    fun failedDownStillRunsInventoriesBaselineComparisonAndSafeRootDeletion() {
        withFixture { fixture ->
            val result = fixture.run("down-fails")

            assertTrue(result.exitCode != 0, result.output)
            assertCleanupInventoriesAndBaselineAfterDown(result.commands)
            assertTrue(
                "baseline-match" in result.output,
                "Successful baseline comparison must still run after failed down",
            )
            assertFalse(Files.exists(fixture.proofRoot))
        }
    }

    @Test
    fun cleanupExactNetworkOrVolumeCollisionRetainsRootAndFailsClosed() {
        listOf(
            "cleanup-exact-network-remains" to
                "mail-sandbox-task5-proof_operator-ingress",
            "cleanup-exact-volume-remains" to
                "mail-sandbox-task5-proof_task5-proof-logs",
        ).forEach { (scenario, exactName) ->
            withFixture { fixture ->
                val result = fixture.run(scenario)

                assertTrue(result.exitCode != 0, "$scenario: ${result.output}")
                assertTrue("baseline-match" in result.output, result.output)
                assertTrue(
                    result.commands.any { it == "fake-name-output $exactName" },
                    result.commands.joinToString("\n"),
                )
                assertCleanupInventoriesAndBaselineAfterDown(result.commands)
                assertTrue(
                    Files.isDirectory(fixture.proofRoot),
                    "Unknown cleanup resources must retain the proof root",
                )
            }
        }
    }

    @Test
    fun successfulLifecycleUsesOnlyFixedServicesAndSecretStdin() {
        withFixture { fixture ->
            val result = fixture.run("success")

            assertEquals(0, result.exitCode, result.output)
            val certificateRequest =
                "openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 " +
                    "-subj /CN=localhost " +
                    "-addext subjectAltName=DNS:localhost " +
                    "-keyout ${fixture.proofRoot}/ssl/tls.key " +
                    "-out ${fixture.proofRoot}/ssl/tls.crt"
            val certificateVerification =
                "openssl verify -CAfile ${fixture.proofRoot}/ssl/tls.crt " +
                    "-verify_hostname localhost " +
                    "${fixture.proofRoot}/ssl/tls.crt"
            val upCommands = result.commands.filter { " compose " in it && " up " in it }
            assertEquals(2, upCommands.size)
            assertTrue(
                upCommands[0].endsWith(
                    "up --detach --build --force-recreate --wait " +
                        "oauth2-mock dovecot postfix",
                ),
            )
            assertTrue(
                upCommands[1].endsWith(
                    "--profile dovecot-operator up --detach --build " +
                        "--force-recreate --no-deps --wait dovecot-operator",
                ),
            )
            assertEquals(
                listOf(
                    "lsof -nP -iTCP:1993 -sTCP:LISTEN",
                    "lsof -nP -iTCP:21995 -sTCP:LISTEN",
                    "lsof -nP -iTCP:2993 -sTCP:LISTEN",
                    "lsof -nP -iTCP:21025 -sTCP:LISTEN",
                    "lsof -nP -iTCP:28080 -sTCP:LISTEN",
                ),
                result.commands.filter { it.startsWith("lsof ") },
            )
            assertOrdered(
                result.commands,
                certificateRequest,
                certificateVerification,
                upCommands.first(),
            )
            assertOrdered(
                result.commands,
                "kotlin test --include-module dashboard-server " +
                    "--include-classes " +
                    "mail.sandbox.dashboard.server.gate.dovecot." +
                    "DovecotOperatorStartupLiveTest",
                "kotlin test --include-module dashboard-server " +
                    "--include-classes " +
                    "mail.sandbox.dashboard.server.gate.dovecot." +
                    "DovecotIsolationLiveTest",
                "kotlin test --include-module dashboard-server " +
                    "--include-classes " +
                    "mail.sandbox.dashboard.server.gate.dovecot." +
                    "DovecotOperatorRotationLiveTest",
                "kotlin run --module dashboard-server --main-class " +
                    "mail.sandbox.dashboard.server.gate.dovecot." +
                    "EligibilityFileCli -- task5-proof remove " +
                    "task5-bootstrap@local.test",
            )
            assertTrue(
                result.commands.none { "task5-fake-secret" in it },
                "Generated passwords must never appear in argv or command logs",
            )
            assertTrue(
                result.commands.none {
                    LOCK_TOKEN_CANARY in it || ROOT_TOKEN_CANARY in it
                },
                "Lifecycle ownership tokens must never appear in command logs",
            )
            assertFalse(
                LOCK_TOKEN_CANARY in result.output ||
                    ROOT_TOKEN_CANARY in result.output,
                "Lifecycle ownership tokens must never appear in process output",
            )
            assertTrue(
                result.commands.any { it == "ownership-tokens-distinct" },
                result.commands.joinToString("\n"),
            )
            val dockerHosts = result.commands.filter {
                it.startsWith("docker-host ")
            }
            assertTrue(dockerHosts.isNotEmpty())
            assertTrue(
                dockerHosts.all { it == FIXED_DOCKER_HOST_LOG },
                dockerHosts.joinToString("\n"),
            )
            val proofEnvironments = result.commands.filter {
                it.startsWith("proof-env ")
            }
            assertEquals(
                listOf(UNSET_PROOF_ENVIRONMENT),
                proofEnvironments.take(1),
            )
            assertTrue(proofEnvironments.drop(1).isNotEmpty())
            assertTrue(
                proofEnvironments.drop(1).all {
                    it == FIXED_PROOF_ENVIRONMENT
                },
                proofEnvironments.joinToString("\n"),
            )
            assertTrue(result.commands.any { it == "proof-modes 700 700 700 600 600" })
            assertTrue(
                result.commands.any {
                    it == "provider-evidence-contract 700 600 600 600 600"
                },
                result.commands.joinToString("\n"),
            )
            assertFalse(Files.exists(fixture.proofRoot))
            assertFalse(
                Files.exists(
                    fixture.lifecycleLock,
                    LinkOption.NOFOLLOW_LINKS,
                ),
            )
        }
    }

    @Test
    fun successfulLifecycleRunsTheExactCheckedTask7Sequence() {
        withFixture { fixture ->
            val result = fixture.run("success")
            val composePrefix =
                "docker compose --project-name mail-sandbox-task5-proof " +
                    "--file docker-compose.yml --file " +
                    "debug-dashboard/dashboard-server/testResources/" +
                    "dovecot-gate0c/compose.task5-proof.yml"
            val nonLiveKotlin =
                "kotlin test --include-module dashboard-server " +
                    TASK7_NON_LIVE_CLASSES.joinToString(" ") {
                        "--include-classes $DOVECOT_GATE_PACKAGE.$it"
                    }
            val certificateRequest =
                "openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 " +
                    "-subj /CN=localhost " +
                    "-addext subjectAltName=DNS:localhost " +
                    "-keyout ${fixture.proofRoot}/ssl/tls.key " +
                    "-out ${fixture.proofRoot}/ssl/tls.crt"
            val certificateVerification =
                "openssl verify -CAfile ${fixture.proofRoot}/ssl/tls.crt " +
                    "-verify_hostname localhost " +
                    "${fixture.proofRoot}/ssl/tls.crt"
            val ordinaryStart =
                "$composePrefix up --detach --build --force-recreate --wait " +
                    "oauth2-mock dovecot postfix"
            val operatorStart =
                "$composePrefix --profile dovecot-operator up --detach " +
                    "--build --force-recreate --no-deps --wait " +
                    "dovecot-operator"
            val baseComposeEvidence =
                "docker compose --file docker-compose.yml " +
                    "--profile dovecot-operator config --format json " +
                    "oauth2-mock dovecot postfix dovecot-operator"
            val proofComposeEvidence =
                "$composePrefix config --format json " +
                    "oauth2-mock dovecot postfix dovecot-operator"
            val operatorStatus =
                "$composePrefix --profile dovecot-operator ps " +
                    "oauth2-mock dovecot postfix dovecot-operator"
            val dovecotVersion =
                "$composePrefix exec -T dovecot dovecot --version"
            val ordinaryConfigEvidence =
                "$composePrefix exec -T dovecot /dovecot/bin/doveconf -n"
            val operatorConfigEvidence =
                "$composePrefix exec -T dovecot-operator " +
                    "/dovecot/bin/doveconf -n"
            val ownedEvidence =
                liveClassCommand("DovecotOperatorOwnedEvidenceLiveTest")
            val operatorHealthcheck =
                "$composePrefix exec -T dovecot-operator " +
                    "/usr/local/bin/operator-healthcheck"
            val eligibilityPreflight =
                "kotlin run --module dashboard-server --main-class " +
                    "$DOVECOT_GATE_PACKAGE.EligibilityFileCli -- " +
                    "task5-proof preflight"
            val bootstrapEligibility =
                "kotlin run --module dashboard-server --main-class " +
                    "$DOVECOT_GATE_PACKAGE.EligibilityFileCli -- " +
                    "task5-proof add task5-bootstrap@local.test"
            val bootstrapCredential =
                "kotlin run --module dashboard-server --main-class " +
                    "$DOVECOT_GATE_PACKAGE." +
                    "DovecotOperatorCredentialStoreCli -- " +
                    "bootstrap-task5-proof"
            val startup = liveClassCommand("DovecotOperatorStartupLiveTest")
            val isolation = liveClassCommand("DovecotIsolationLiveTest")
            val rotation = liveClassCommand("DovecotOperatorRotationLiveTest")
            val exec = liveClassCommand("DovecotOperatorExecTransportLiveTest")
            val cleanupEligibility =
                "kotlin run --module dashboard-server --main-class " +
                    "$DOVECOT_GATE_PACKAGE.EligibilityFileCli -- " +
                    "task5-proof remove task5-bootstrap@local.test"
            val cleanup =
                "$composePrefix down --volumes --remove-orphans"

            assertEquals(0, result.exitCode, result.output)
            assertOrdered(
                result.commands,
                "docker ps --all --quiet --filter " +
                    "label=com.docker.compose.project=" +
                    "mail-sandbox-task5-proof",
                "docker ps --all --quiet --filter " +
                    "name=^/mail-sandbox-task5-proof-dovecot-1$",
                "docker network ls --quiet --filter " +
                    "name=^mail-sandbox-task5-proof_operator-ingress$",
                "docker volume ls --quiet --filter " +
                    "name=^mail-sandbox-task5-proof_task5-proof-logs$",
                "docker ps --all --quiet --no-trunc --filter " +
                    "label=com.docker.compose.project=dovecot-docker " +
                    "--filter label=com.docker.compose.service=dovecot",
                "docker ps --all --quiet --no-trunc --filter " +
                    "label=com.docker.compose.project=dovecot-docker " +
                    "--filter label=com.docker.compose.service=postfix",
                "docker ps --all --quiet --no-trunc --filter " +
                    "label=com.docker.compose.project=dovecot-docker " +
                    "--filter label=com.docker.compose.service=oauth2-mock",
                "lsof -nP -iTCP:2993 -sTCP:LISTEN",
                nonLiveKotlin,
                "python3 -m unittest " +
                    "debug-dashboard/dashboard-server/testResources/" +
                    "dovecot-gate0c/test_network_isolation_check.py",
                "docker compose --file docker-compose.yml config --quiet " +
                    "oauth2-mock dovecot postfix",
                "$composePrefix config --quiet oauth2-mock dovecot postfix " +
                    "dovecot-operator",
                baseComposeEvidence,
                proofComposeEvidence,
                certificateRequest,
                certificateVerification,
                ordinaryStart,
                eligibilityPreflight,
                bootstrapEligibility,
                bootstrapCredential,
                operatorStart,
                operatorStatus,
                dovecotVersion,
                ordinaryConfigEvidence,
                operatorConfigEvidence,
                ownedEvidence,
                "provider-evidence-contract 700 600 600 600 600",
                operatorHealthcheck,
                exec,
                execModeTranscript("preflight"),
                startup,
                isolation,
                rotation,
                exec,
                execModeTranscript("full"),
                exec,
                execModeTranscript("inventory-only"),
                cleanupEligibility,
                cleanup,
            )
            assertEquals(
                listOf(ordinaryStart, operatorStart),
                result.commands.filter { " compose " in it && " up " in it },
            )
            assertEquals(
                listOf(
                    execModeTranscript("preflight"),
                    execModeTranscript("full"),
                    execModeTranscript("inventory-only"),
                ),
                result.commands.filter {
                    it.startsWith("task5-exec-proof-mode ")
                },
                "Checkpoint modes must be scoped to their exact invocations",
            )
            assertTrue(
                result.commands.none {
                    "stalwart" in it.lowercase()
                },
                result.commands.joinToString("\n"),
            )
        }
    }

    @Test
    fun lifecycleSourceScopesExactExecCheckpointsAndIsolatedOperatorStart() {
        val source = Files.readString(lifecycleScript)
        val operatorStart = """
            |task5_compose_with_lock \
            |  --profile dovecot-operator \
            |  up --detach --build --force-recreate --no-deps --wait \
            |  dovecot-operator
        """.trimMargin()
        val preflight = """
            |TASK5_OPERATOR_EXEC_PROOF_MODE=preflight \
            |    "${'$'}TASK5_KOTLIN" test \
            |      --include-module dashboard-server \
            |      --include-classes "${'$'}TASK5_EXEC_TRANSPORT_LIVE_CLASS"
        """.trimMargin()
        val finalInventory = """
            |TASK5_OPERATOR_EXEC_PROOF_MODE=inventory-only \
            |    "${'$'}TASK5_KOTLIN" test \
            |      --include-module dashboard-server \
            |      --include-classes "${'$'}TASK5_EXEC_TRANSPORT_LIVE_CLASS"
        """.trimMargin()

        assertTrue(operatorStart in source)
        assertTrue(preflight in source)
        assertTrue(finalInventory in source)
        assertFalse("export TASK5_OPERATOR_EXEC_PROOF_MODE" in source)
        assertEquals(
            1,
            source.windowed(
                "TASK5_OPERATOR_EXEC_PROOF_MODE=preflight".length,
            ).count {
                it == "TASK5_OPERATOR_EXEC_PROOF_MODE=preflight"
            },
        )
        assertEquals(
            1,
            source.windowed(
                "TASK5_OPERATOR_EXEC_PROOF_MODE=inventory-only".length,
            ).count {
                it == "TASK5_OPERATOR_EXEC_PROOF_MODE=inventory-only"
            },
        )
        assertFalse(
            Regex("""\bup\b[^\n]*\bdovecot-operator\b[^\n]*\b(?:dovecot|postfix|oauth2-mock)\b""")
                .containsMatchIn(source),
        )
    }

    @Test
    fun everyTask7CheckpointFailureStillRunsCheckedCleanup() {
        listOf(
            "task7-preflight-fails",
            "task7-exec-full-fails",
            "task7-final-inventory-fails",
        ).forEach { scenario ->
            withFixture { fixture ->
                val result = fixture.run(scenario)

                assertTrue(result.exitCode != 0, "$scenario: ${result.output}")
                assertCleanupInventoriesAndBaselineAfterDown(result.commands)
                assertFalse(
                    Files.exists(fixture.proofRoot, LinkOption.NOFOLLOW_LINKS),
                    "$scenario retained the owned proof root",
                )
                assertFalse(
                    Files.exists(fixture.lifecycleLock, LinkOption.NOFOLLOW_LINKS),
                    "$scenario retained the owned lifecycle lock",
                )
            }
        }
    }

    @Test
    fun failedCertificateHostnameVerificationStartsNoComposeService() {
        withFixture { fixture ->
            val result = fixture.run("certificate-verification-fails")
            val expectedVerification =
                "openssl verify -CAfile ${fixture.proofRoot}/ssl/tls.crt " +
                    "-verify_hostname localhost " +
                    "${fixture.proofRoot}/ssl/tls.crt"

            assertTrue(result.exitCode != 0, result.output)
            assertTrue(
                result.commands.any { it == expectedVerification },
                result.commands.joinToString("\n"),
            )
            assertTrue(
                result.commands.none { " compose " in it && " up " in it },
                result.commands.joinToString("\n"),
            )
            assertFalse(
                Files.exists(fixture.proofRoot, LinkOption.NOFOLLOW_LINKS),
                "Failed certificate verification must clean the proof root",
            )
            assertFalse(
                Files.exists(fixture.lifecycleLock, LinkOption.NOFOLLOW_LINKS),
                "Failed certificate verification must release the lifecycle lock",
            )
        }
    }

    @Test
    fun importedExportAttributesXtraceAndAllexportCannotLeakOwnershipTokens() {
        withFixture { fixture ->
            val ambientLock = "ambient-lock-token-sentinel"
            val ambientRoot = "ambient-root-token-sentinel"
            val ambientLocal = "ambient-local-token-sentinel"
            val ambientActual = "ambient-actual-token-sentinel"
            val result = fixture.run(
                scenario = "success",
                extraEnvironment = mapOf(
                    "TASK5_LIFECYCLE_LOCK_TOKEN" to ambientLock,
                    "TASK5_PROOF_ROOT_TOKEN" to ambientRoot,
                    "token" to ambientLocal,
                    "actual_token" to ambientActual,
                    "SHELLOPTS" to "xtrace:allexport",
                    "TASK5_FAKE_GUARD_CHILD_ENV" to "1",
                ),
                timeout = CHILD_ENV_GUARD_PROCESS_TIMEOUT,
            )
            val transcript = buildString {
                append(result.output)
                append('\n')
                append(result.commands.joinToString("\n"))
            }

            assertEquals(0, result.exitCode, transcript)
            listOf(
                LOCK_TOKEN_CANARY,
                ROOT_TOKEN_CANARY,
                ambientLock,
                ambientRoot,
                ambientLocal,
                ambientActual,
            ).forEach { forbidden ->
                assertFalse(
                    forbidden in transcript,
                    "A token leaked through trace, logs, or a child environment",
                )
            }
            assertTrue(
                result.commands.any { it == "child-env-clean stat" },
                result.commands.joinToString("\n"),
            )
            assertFalse(
                result.commands.any { it.startsWith("child-env-leak ") },
                result.commands.joinToString("\n"),
            )
        }
    }

    @Test
    fun privilegedCleanStartupSuppressesBashEnvAndImportedToolFunctions() {
        withFixture { fixture ->
            val result = fixture.run(
                scenario = "success",
                extraEnvironment = fixture.hostileStartupEnvironment(),
            )
            val injectionTranscript = fixture.startupInjectionTranscript()
            val completeTranscript = buildString {
                append(result.output)
                append('\n')
                append(result.commands.joinToString("\n"))
                append('\n')
                append(injectionTranscript)
            }

            assertEquals(0, result.exitCode, completeTranscript)
            assertTrue(
                injectionTranscript.isEmpty(),
                "BASH_ENV or an imported function ran before the clean stage:\n" +
                    injectionTranscript,
            )
            assertFalse(
                "injected-stat" in completeTranscript ||
                    "injected-docker" in completeTranscript ||
                    "debug-token" in completeTranscript,
                completeTranscript,
            )
            assertFalse(LOCK_TOKEN_CANARY in completeTranscript)
            assertFalse(ROOT_TOKEN_CANARY in completeTranscript)
            val dockerHosts = result.commands.filter {
                it.startsWith("docker-host ")
            }
            assertTrue(dockerHosts.isNotEmpty())
            assertTrue(
                dockerHosts.all { it == FIXED_DOCKER_HOST_LOG },
                dockerHosts.joinToString("\n"),
            )
            assertFalse(Files.exists(fixture.proofRoot))
            assertFalse(
                Files.exists(
                    fixture.lifecycleLock,
                    LinkOption.NOFOLLOW_LINKS,
                ),
            )
        }
    }

    @Test
    fun argumentsAmbientOverridesAndSymlinkedScriptAreRejectedBeforeCommands() {
        withFixture { fixture ->
            val argumentResult = fixture.run("success", arguments = listOf("unexpected"))
            assertTrue(argumentResult.exitCode != 0)
            assertTrue(argumentResult.commands.isEmpty())
            assertFalse(Files.exists(fixture.proofRoot))
        }
        withFixture { fixture ->
            val ambientResult = fixture.run(
                "success",
                extraEnvironment = mapOf("COMPOSE_PROJECT_NAME" to "wrong-project"),
            )
            assertTrue(ambientResult.exitCode != 0)
            assertTrue(ambientResult.commands.isEmpty())
            assertFalse(Files.exists(fixture.proofRoot))
        }
        withFixture { fixture ->
            val forgedCleanStage = fixture.run(
                "success",
                extraEnvironment = mapOf("TASK5_CLEAN_STAGE" to "1"),
            )
            assertTrue(forgedCleanStage.exitCode != 0)
            assertTrue(forgedCleanStage.commands.isEmpty())
            assertFalse(Files.exists(fixture.proofRoot))
            assertFalse(
                Files.exists(
                    fixture.lifecycleLock,
                    LinkOption.NOFOLLOW_LINKS,
                ),
            )
        }
        withFixture { fixture ->
            val exactForgedCleanStage =
                fixture.runExactForgedCleanStageWithInvalidTmpdir()
            assertTrue(exactForgedCleanStage.exitCode != 0)
            assertTrue(
                exactForgedCleanStage.commands.isEmpty(),
                exactForgedCleanStage.commands.joinToString("\n"),
            )
            assertFalse(Files.exists(fixture.proofRoot))
            assertFalse(
                Files.exists(
                    fixture.lifecycleLock,
                    LinkOption.NOFOLLOW_LINKS,
                ),
            )
        }
        withFixture { fixture ->
            val realScript = fixture.repositoryRoot.resolve("outside-script")
            Files.copy(fixture.script, realScript)
            Files.delete(fixture.script)
            Files.createSymbolicLink(fixture.script, realScript)

            val symlinkResult = fixture.run("success")

            assertTrue(symlinkResult.exitCode != 0)
            assertTrue(symlinkResult.commands.isEmpty())
            assertFalse(Files.exists(fixture.proofRoot))
        }
    }

    @Test
    fun symlinkedRuntimeAncestorIsRejectedWithoutTouchingExternalState() {
        withFixture { fixture ->
            val external = fixture.replaceRuntimeWithExternalSymlink()

            val result = fixture.run("success")

            assertTrue(result.exitCode != 0, result.output)
            assertTrue(result.commands.isEmpty(), result.commands.joinToString("\n"))
            assertEquals("keep\n", Files.readString(external.resolve("sentinel")))
            assertFalse(Files.exists(external.resolve("task5-proof")))
            assertTrue(Files.isSymbolicLink(fixture.runtimeRoot))
        }
    }

    @Test
    fun symlinkedDaemonGlobalLockParentIsRejectedBeforeEntropyOrCommands() {
        withFixture { fixture ->
            val sentinel = fixture.replaceLifecycleLockParentWithSymlink()

            val result = fixture.run("success")

            assertTrue(result.exitCode != 0, result.output)
            assertTrue(result.commands.isEmpty(), result.commands.joinToString("\n"))
            assertEquals("foreign\n", Files.readString(sentinel))
            assertFalse(
                Files.exists(
                    fixture.lifecycleLock,
                    LinkOption.NOFOLLOW_LINKS,
                ),
            )
        }
    }

    @Test
    fun lifecycleLockEntropyFailureLeavesNoPartialGlobalLock() {
        withFixture { fixture ->
            val result = fixture.run("lock-token-generation-fails")

            assertTrue(result.exitCode != 0, result.output)
            assertTrue(
                result.commands.none {
                    it.startsWith("docker ") ||
                        it.startsWith("kotlin ") ||
                        it.startsWith("mkdir ")
                },
                result.commands.joinToString("\n"),
            )
            assertFalse(Files.exists(fixture.proofRoot))
            assertFalse(
                Files.exists(
                    fixture.lifecycleLock,
                    LinkOption.NOFOLLOW_LINKS,
                ),
            )
        }
    }

    @Test
    fun intAndTermAfterGlobalLockMkdirAreDeferredThroughOwnedCleanup() {
        mapOf(
            "INT" to 130,
            "TERM" to 143,
        ).forEach { (signal, expectedStatus) ->
            withFixture { fixture ->
                val result =
                    fixture.runSignalledAfterGlobalLockMkdir(signal)

                assertEquals(
                    expectedStatus,
                    result.exitCode,
                    "$signal: ${result.output}",
                )
                val lockMkdir = result.commands.indexOfFirst {
                    it == "mkdir -m 700 ${fixture.lifecycleLock}"
                }
                assertTrue(
                    lockMkdir >= 0,
                    result.commands.joinToString("\n"),
                )
                assertCleanupInventoriesAfter(
                    commands = result.commands,
                    boundary = lockMkdir,
                )
                assertFalse(
                    result.commands.any {
                        it.startsWith("kotlin ") ||
                            " compose " in it && (
                                " up " in it ||
                                    " down " in it
                                )
                    },
                    result.commands.joinToString("\n"),
                )
                assertFalse(
                    "partial lifecycle lock is retained" in result.output,
                    result.output,
                )
                assertFalse(Files.exists(fixture.proofRoot))
                assertFalse(
                    Files.exists(
                        fixture.lifecycleLock,
                        LinkOption.NOFOLLOW_LINKS,
                    ),
                )
                assertFalse(
                    fixture.hasBaselineDirectory(),
                    "No baseline directory may survive $signal cleanup",
                )
            }
        }
    }

    @Test
    fun intAndTermAfterBaselineMktempAreDeferredThroughIncompleteBaselineCleanup() {
        mapOf(
            "INT" to 130,
            "TERM" to 143,
        ).forEach { (signal, expectedStatus) ->
            withFixture { fixture ->
                val result =
                    fixture.runSignalledAfterBaselineMktemp(signal)

                assertEquals(
                    expectedStatus,
                    result.exitCode,
                    "$signal: ${result.output}",
                )
                val baselineAllocation = result.commands.indexOfFirst {
                    it.startsWith("mktemp -d ") &&
                        "mail-sandbox-task5-baseline.XXXXXX" in it
                }
                assertTrue(
                    baselineAllocation >= 0,
                    result.commands.joinToString("\n"),
                )
                assertCleanupInventoriesAfter(
                    commands = result.commands,
                    boundary = baselineAllocation,
                )
                assertFalse(
                    result.commands.any {
                        it.startsWith("kotlin ") ||
                            " compose " in it && (
                                " up " in it ||
                                    " down " in it
                                )
                    },
                    result.commands.joinToString("\n"),
                )
                assertFalse(
                    fixture.hasBaselineDirectory(),
                    "No baseline directory may survive $signal cleanup",
                )
                assertFalse(Files.exists(fixture.proofRoot))
                assertFalse(
                    Files.exists(
                        fixture.lifecycleLock,
                        LinkOption.NOFOLLOW_LINKS,
                    ),
                )
            }
        }
    }

    @Test
    fun createdButUnpublishedGlobalLockIsReportedAndRetainedWithoutInference() {
        withFixture { fixture ->
            val result = fixture.run("global-lock-mkdir-created-then-fails")

            assertEquals(74, result.exitCode, result.output)
            assertTrue(
                "partial lifecycle lock is retained without inferred ownership" in
                    result.output,
                result.output,
            )
            assertTrue(
                Files.isDirectory(
                    fixture.lifecycleLock,
                    LinkOption.NOFOLLOW_LINKS,
                ),
            )
            assertFalse(
                Files.exists(
                    fixture.lifecycleLock.resolve("owner"),
                    LinkOption.NOFOLLOW_LINKS,
                ),
            )
            assertTrue(
                result.commands.none {
                    it.startsWith("docker ") ||
                        it.startsWith("kotlin ") ||
                        " compose " in it
                },
                result.commands.joinToString("\n"),
            )
            assertFalse(Files.exists(fixture.proofRoot))
        }
    }

    @Test
    fun criticalOperationFailureWinsOverAQueuedSignal() {
        mapOf(
            "INT" to 130,
            "TERM" to 143,
        ).forEach { (signal, signalStatus) ->
            withFixture { fixture ->
                val result =
                    fixture.runSignalledDuringFailingGlobalLockMkdir(signal)

                assertEquals(75, result.exitCode, "$signal: ${result.output}")
                assertTrue(
                    "primary failure 75 preserved; deferred signal " +
                        "$signalStatus observed during mandatory cleanup" in
                        result.output,
                    result.output,
                )
                assertTrue(
                    "partial lifecycle lock is retained without " +
                        "inferred ownership" in result.output,
                    result.output,
                )
                assertTrue(
                    Files.isDirectory(
                        fixture.lifecycleLock,
                        LinkOption.NOFOLLOW_LINKS,
                    ),
                )
                assertFalse(
                    Files.exists(
                        fixture.lifecycleLock.resolve("owner"),
                        LinkOption.NOFOLLOW_LINKS,
                    ),
                )
                assertTrue(
                    result.commands.none {
                        it.startsWith("docker ") ||
                            it.startsWith("kotlin ") ||
                            " compose " in it
                    },
                    result.commands.joinToString("\n"),
                )
                assertFalse(Files.exists(fixture.proofRoot))
            }
        }
    }

    @Test
    fun termDuringPausedComposeDownCannotInterruptMandatoryCleanup() {
        withFixture { fixture ->
            val result = fixture.runSignalledDuringCleanupDown("TERM")

            assertEquals(23, result.exitCode, result.output)
            assertCleanupInventoriesAndBaselineAfterDown(result.commands)
            assertTrue("baseline-match" in result.output, result.output)
            assertFalse(Files.exists(fixture.proofRoot))
            assertFalse(
                Files.exists(
                    fixture.lifecycleLock,
                    LinkOption.NOFOLLOW_LINKS,
                ),
            )
            assertFalse(
                fixture.hasBaselineDirectory(),
                "Mandatory cleanup must remove the matched baseline",
            )
        }
    }

    @Test
    fun intAndTermDuringSuccessfulCleanupWinAfterMandatoryTeardown() {
        mapOf(
            "INT" to 130,
            "TERM" to 143,
        ).forEach { (signal, expectedStatus) ->
            withFixture { fixture ->
                val result =
                    fixture.runSignalledDuringSuccessfulCleanupDown(signal)

                assertEquals(
                    expectedStatus,
                    result.exitCode,
                    "$signal: ${result.output}",
                )
                assertCleanupInventoriesAndBaselineAfterDown(result.commands)
                assertTrue("baseline-match" in result.output, result.output)
                assertFalse(Files.exists(fixture.proofRoot))
                assertFalse(
                    Files.exists(
                        fixture.lifecycleLock,
                        LinkOption.NOFOLLOW_LINKS,
                    ),
                )
                assertFalse(
                    fixture.hasBaselineDirectory(),
                    "Mandatory cleanup must finish before honoring $signal",
                )
            }
        }
    }

    @Test
    fun foreignRootInsertedBeforeExclusiveMkdirIsNeverAdoptedOrDeleted() {
        withFixture { fixture ->
            val result = fixture.run("foreign-root-before-mkdir")

            assertEquals(73, result.exitCode, result.output)
            val mkdir = result.commands.indexOfFirst {
                it == "mkdir ${fixture.proofRoot}"
            }
            val cleanupInventory = result.commands.indexOfFirstAfter(mkdir) {
                it.startsWith("docker ps --all --quiet --filter ")
            }
            val baselineInspect = result.commands.indexOfFirstAfter(cleanupInventory) {
                it.startsWith("docker inspect --format ")
            }
            assertTrue(mkdir >= 0, result.commands.joinToString("\n"))
            assertTrue(cleanupInventory > mkdir, result.commands.joinToString("\n"))
            assertTrue(baselineInspect > cleanupInventory, result.commands.joinToString("\n"))
            assertTrue("baseline-match" in result.output, result.output)
            assertEquals(
                "foreign\n",
                Files.readString(fixture.proofRoot.resolve("sentinel")),
            )
            assertTrue(Files.isDirectory(fixture.lifecycleLock))
            assertNoProofMutation(result.commands)
        }
    }

    @Test
    fun runtimeSwapAfterCreationFailsCleanupAndRetainsOriginalRootEvidence() {
        withFixture { fixture ->
            val result = fixture.run("runtime-swapped-before-cleanup")
            val evidence = fixture.runtimeSwapEvidence()

            assertEquals(23, result.exitCode, result.output)
            assertTrue(
                "primary failure 23 preserved; cleanup also failed" in result.output,
                result.output,
            )
            assertTrue("baseline-match" in result.output, result.output)
            assertTrue(Files.isSymbolicLink(fixture.runtimeRoot))
            assertEquals("keep\n", Files.readString(evidence.externalSentinel))
            assertFalse(Files.exists(evidence.externalRuntime.resolve("task5-proof")))
            assertTrue(
                Files.isDirectory(evidence.movedRuntime.resolve("task5-proof")),
                "The original proof root must be retained as cleanup evidence",
            )
            assertFalse(
                result.commands.any {
                    "task5-proof remove task5-bootstrap@local.test" in it
                },
                "Bootstrap removal must not follow an unsafe runtime ancestor",
            )
            assertTrue(
                result.commands.any { " compose " in it && " down " in it },
                "The daemon-global lock remains owned after a checkout runtime swap",
            )
            assertCleanupInventoriesAndBaselineAfterDown(result.commands)
            assertTrue(Files.isDirectory(fixture.lifecycleLock))
        }
    }

    @Test
    fun distinctRepositoryRootsSerializeAgainstOneSharedDaemonLock() {
        withFixture { fixture ->
            val concurrent =
                fixture.runConcurrentDistinctRepositoryHolderAndContender()

            assertEquals(0, concurrent.holder.exitCode, concurrent.holder.output)
            assertTrue(
                concurrent.contender.exitCode != 0,
                concurrent.contender.output,
            )
            assertTrue(concurrent.lockIdentityWasStableDuringContention)
            assertTrue(concurrent.proofRootsWereAbsentDuringContention)
            assertTrue(
                concurrent.contender.commands.none {
                    it.startsWith("docker ") ||
                        it.startsWith("kotlin ") ||
                        " compose " in it
                },
                concurrent.contender.commands.joinToString("\n"),
            )
            assertEquals(
                0,
                concurrent.successor.exitCode,
                concurrent.successor.output,
            )
            assertTrue(concurrent.repositoriesWerePhysicallyDistinct)
            assertTrue(concurrent.proofRootsWereAbsentAfterSuccessor)
            assertFalse(Files.exists(fixture.proofRoot))
            assertFalse(
                Files.exists(
                    fixture.lifecycleLock,
                    LinkOption.NOFOLLOW_LINKS,
                ),
            )
        }
    }

    @Test
    fun preexistingLockCollisionMalformedOwnerSymlinkOrUnsafeModeIsNeverRemoved() {
        listOf(
            ForeignLockKind.COLLISION,
            ForeignLockKind.MALFORMED_OWNER,
            ForeignLockKind.SYMLINK,
            ForeignLockKind.UNSAFE_MODE,
        ).forEach { kind ->
            withFixture { fixture ->
                val sentinel = fixture.installForeignLock(kind)

                val result = fixture.run("success")

                assertTrue(result.exitCode != 0, "$kind: ${result.output}")
                assertTrue(
                    result.commands.none {
                        it.startsWith("docker ") ||
                            it.startsWith("kotlin ") ||
                            it == "mkdir ${fixture.proofRoot}" ||
                            " compose " in it
                    },
                    result.commands.joinToString("\n"),
                )
                assertEquals("foreign\n", Files.readString(sentinel))
                assertTrue(
                    Files.exists(
                        fixture.lifecycleLock,
                        LinkOption.NOFOLLOW_LINKS,
                    ),
                )
                assertFalse(Files.exists(fixture.proofRoot))
            }
        }
    }

    @Test
    fun replacedOrRetokenedOwnedRootSkipsWritersButStillDowns() {
        listOf(
            "root-replaced-before-cleanup",
            "root-marker-inode-changed-before-cleanup",
            "root-marker-token-changed-before-cleanup",
        ).forEach { scenario ->
            withFixture { fixture ->
                val result = fixture.run(scenario)

                assertEquals(23, result.exitCode, "$scenario: ${result.output}")
                assertFalse(
                    result.commands.any {
                        "task5-proof remove task5-bootstrap@local.test" in it
                    },
                    result.commands.joinToString("\n"),
                )
                assertTrue(
                    result.commands.any {
                        " compose " in it && " down " in it
                    },
                    result.commands.joinToString("\n"),
                )
                assertCleanupInventoriesAndBaselineAfterDown(result.commands)
                assertEquals(
                    "foreign\n",
                    Files.readString(fixture.proofRoot.resolve("sentinel")),
                )
                assertTrue(Files.isDirectory(fixture.lifecycleLock))
                if (scenario == "root-replaced-before-cleanup") {
                    assertTrue(
                        Files.isDirectory(
                            fixture.stateDirectory.resolve(
                                "original-proof-root",
                            ),
                        ),
                    )
                }
            }
        }
    }

    @Test
    fun replacedRetokenedOrRemodedOwnedLockSkipsEveryCleanupMutation() {
        listOf(
            "lock-replaced-before-cleanup",
            "lock-marker-inode-changed-before-cleanup",
            "lock-marker-token-changed-before-cleanup",
            "lock-mode-changed-before-cleanup",
        ).forEach { scenario ->
            withFixture { fixture ->
                val result = fixture.run(scenario)
                val live = result.commands.indexOfLast {
                    "DovecotOperatorStartupLiveTest" in it
                }

                assertEquals(23, result.exitCode, "$scenario: ${result.output}")
                assertFalse(
                    result.commands.drop(live + 1).any {
                        "task5-proof remove task5-bootstrap@local.test" in it ||
                            " compose " in it && " down " in it
                    },
                    result.commands.joinToString("\n"),
                )
                assertCleanupInventoriesAndBaselineAfter(
                    result.commands,
                    live,
                )
                assertTrue(Files.isDirectory(fixture.proofRoot))
                assertEquals(
                    "foreign\n",
                    Files.readString(fixture.lifecycleLock.resolve("sentinel")),
                )
                assertTrue(
                    Files.exists(
                        fixture.lifecycleLock,
                        LinkOption.NOFOLLOW_LINKS,
                    ),
                )
            }
        }
    }

    @Test
    fun lockLostDuringBootstrapCleanupCannotFallThroughToComposeDown() {
        withFixture { fixture ->
            val result = fixture.run(
                "lock-changed-during-bootstrap-cleanup",
            )
            val bootstrapRemoval = result.commands.indexOfLast {
                "task5-proof remove task5-bootstrap@local.test" in it
            }

            assertEquals(23, result.exitCode, result.output)
            assertTrue(
                bootstrapRemoval >= 0,
                result.commands.joinToString("\n"),
            )
            assertFalse(
                result.commands.drop(bootstrapRemoval + 1).any {
                    " compose " in it && " down " in it
                },
                result.commands.joinToString("\n"),
            )
            assertCleanupInventoriesAndBaselineAfter(
                result.commands,
                bootstrapRemoval,
            )
            assertTrue(Files.isDirectory(fixture.proofRoot))
            assertEquals(
                "foreign\n",
                Files.readString(fixture.lifecycleLock.resolve("sentinel")),
            )
        }
        withFixture { fixture ->
            val result = fixture.run("lock-extra-entry-before-cleanup")

            assertEquals(23, result.exitCode, result.output)
            assertTrue(
                result.commands.any {
                    "task5-proof remove task5-bootstrap@local.test" in it
                },
                result.commands.joinToString("\n"),
            )
            assertCleanupInventoriesAndBaselineAfterDown(result.commands)
            assertFalse(Files.exists(fixture.proofRoot))
            assertEquals(
                "foreign\n",
                Files.readString(fixture.lifecycleLock.resolve("sentinel")),
            )
            assertTrue(
                Files.exists(
                    fixture.lifecycleLock.resolve("owner"),
                    LinkOption.NOFOLLOW_LINKS,
                ),
                "Release must validate unknown content before removing its marker",
            )
        }
    }

    @Test
    fun planAndGateEvidenceUseOneCheckedLifecycleInvocation() {
        val relativeScript =
            "debug-dashboard/dashboard-server/testResources/" +
                "dovecot-gate0c/run-task5-proof.sh"
        val task5 = Files.readString(implementationPlan)
            .substringAfter("## Task 5:")
            .substringBefore("## Task 6:")
        val evidence = Files.readString(gateEvidence)
            .substringAfter("## Task 5 isolated operator-ingress proof")
            .substringBefore("## Verification")

        assertTrue("./$relativeScript" in task5)
        assertFalse("Phase 1 —" in task5)
        assertFalse("Phase 2 —" in task5)
        assertFalse("Phase 3 —" in task5)
        assertFalse("Phase 4 —" in task5)
        assertTrue("fail-closed lifecycle" in task5)
        val bashBlocks = Regex(
            """```bash\n([\s\S]*?)\n```""",
        ).findAll(task5).map { it.groupValues[1].trim() }.toList()
        assertEquals(listOf("./$relativeScript"), bashBlocks)
        assertTrue(
            bashBlocks.none {
                "docker compose" in it ||
                    "bootstrap" in it ||
                    "DovecotOperatorCredentialStoreCli" in it
            },
        )
        assertTrue("`$relativeScript`" in evidence)
        assertTrue("fail-closed lifecycle" in evidence)
        assertTrue("DOCKER_HOST=unix:///var/run/docker.sock" in task5)
        assertTrue("DOCKER_HOST=unix:///var/run/docker.sock" in evidence)
        assertTrue("lifecycle lock" in task5)
        assertTrue("lifecycle lock" in evidence)
        assertTrue("`115/115`" in evidence)
        assertTrue("`33/33`" in evidence)
    }

    private fun liveClassCommand(simpleName: String): String =
        "kotlin test --include-module dashboard-server " +
            "--include-classes $DOVECOT_GATE_PACKAGE.$simpleName"

    private fun execModeTranscript(mode: String): String =
        "task5-exec-proof-mode $mode"

    private fun assertNoProofMutation(commands: List<String>) {
        assertFalse(commands.any { " compose " in it && " up " in it })
        assertFalse(commands.any { " compose " in it && " down " in it })
        assertFalse(commands.any { "task5-proof add" in it })
        assertFalse(commands.any { "bootstrap-task5-proof" in it })
    }

    private fun assertNoPreflightExecution(commands: List<String>) {
        assertFalse(
            commands.any { it.startsWith("kotlin ") },
            commands.joinToString("\n"),
        )
        assertFalse(
            commands.any { " compose " in it },
            commands.joinToString("\n"),
        )
    }

    private fun assertCleanupInventoriesAndBaselineAfterDown(commands: List<String>) {
        val down = commands.indexOfFirst { " compose " in it && " down " in it }
        assertTrue(down >= 0, commands.joinToString("\n"))
        assertCleanupInventoriesAndBaselineAfter(commands, down)
    }

    private fun assertCleanupInventoriesAndBaselineAfter(
        commands: List<String>,
        boundary: Int,
    ) {
        val volumes = assertCleanupInventoriesAfter(commands, boundary)
        val baselineInspect = commands.indexOfFirstAfter(volumes) {
            it.startsWith("docker inspect --format ")
        }
        assertTrue(baselineInspect > volumes, commands.joinToString("\n"))
    }

    private fun assertCleanupInventoriesAfter(
        commands: List<String>,
        boundary: Int,
    ): Int {
        val containers = commands.indexOfFirstAfter(boundary) {
            it.startsWith("docker ps --all --quiet --filter ")
        }
        val networks = commands.indexOfFirstAfter(containers) {
            it.startsWith("docker network ls --quiet --filter ")
        }
        val volumes = commands.indexOfFirstAfter(networks) {
            it.startsWith("docker volume ls --quiet --filter ")
        }
        assertTrue(containers > boundary, commands.joinToString("\n"))
        assertTrue(networks > containers, commands.joinToString("\n"))
        assertTrue(volumes > networks, commands.joinToString("\n"))
        return volumes
    }

    private fun assertOrdered(commands: List<String>, vararg expected: String) {
        var previous = -1
        expected.forEach { command ->
            val index = commands.indexOfFirstAfter(previous) { it == command }
            assertTrue(index > previous, commands.joinToString("\n"))
            previous = index
        }
    }

    private fun List<String>.indexOfFirstAfter(
        start: Int,
        predicate: (String) -> Boolean,
    ): Int {
        for (index in (start + 1)..lastIndex) {
            if (predicate(this[index])) return index
        }
        return -1
    }

    private fun withFixture(block: (LifecycleFixture) -> Unit) {
        val sandbox = Files.createTempDirectory("task5-proof-lifecycle-").toRealPath()
        try {
            block(LifecycleFixture.create(sandbox, lifecycleScript))
        } finally {
            Files.walk(sandbox).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    private fun repositoryRoot(): Path {
        val workingDirectory = Path.of(System.getProperty("user.dir"))
            .toAbsolutePath()
            .normalize()
        val dashboardRoot = when (workingDirectory.fileName?.toString()) {
            "dashboard-server" -> workingDirectory.parent
            "debug-dashboard" -> workingDirectory
            else -> error("unexpected Kotlin test working directory")
        }
        return requireNotNull(dashboardRoot.parent)
    }

    private data class ProcessResult(
        val exitCode: Int,
        val output: String,
    )

    private data class LifecycleResult(
        val exitCode: Int,
        val output: String,
        val commands: List<String>,
    )

    private data class ConcurrentLifecycleResult(
        val holder: LifecycleResult,
        val contender: LifecycleResult,
        val successor: LifecycleResult,
        val lockIdentityWasStableDuringContention: Boolean,
        val proofRootsWereAbsentDuringContention: Boolean,
        val proofRootsWereAbsentAfterSuccessor: Boolean,
        val repositoriesWerePhysicallyDistinct: Boolean,
    )

    private enum class ForeignLockKind {
        COLLISION,
        MALFORMED_OWNER,
        SYMLINK,
        UNSAFE_MODE,
    }

    private class LifecycleFixture private constructor(
        val repositoryRoot: Path,
        val script: Path,
        val proofRoot: Path,
        val runtimeRoot: Path,
        private val fakeBin: Path,
        private val commandLog: Path,
        val stateDirectory: Path,
        private val temporaryDirectory: Path,
        val lifecycleLock: Path,
    ) {
        fun replaceRuntimeWithExternalSymlink(): Path {
            val external = repositoryRoot.resolveSibling("external-runtime")
            Files.delete(runtimeRoot)
            external.createDirectories()
            Files.writeString(external.resolve("sentinel"), "keep\n")
            Files.createSymbolicLink(runtimeRoot, external)
            return external
        }

        fun replaceLifecycleLockParentWithSymlink(): Path {
            val parent = requireNotNull(lifecycleLock.parent)
            val external = parent.resolveSibling("foreign-global-lock-parent")
            Files.delete(parent)
            external.createDirectories()
            val sentinel = external.resolve("sentinel")
            Files.writeString(sentinel, "foreign\n")
            Files.createSymbolicLink(parent, external)
            return sentinel
        }

        fun runtimeSwapEvidence(): RuntimeSwapEvidence = RuntimeSwapEvidence(
            movedRuntime = stateDirectory.resolve("moved-runtime"),
            externalRuntime = stateDirectory.resolve("external-runtime"),
            externalSentinel = stateDirectory.resolve("external-runtime/sentinel"),
        )

        fun installForeignLock(kind: ForeignLockKind): Path {
            return when (kind) {
                ForeignLockKind.COLLISION,
                ForeignLockKind.MALFORMED_OWNER,
                ForeignLockKind.UNSAFE_MODE,
                -> {
                    Files.createDirectory(lifecycleLock)
                    Files.setPosixFilePermissions(
                        lifecycleLock,
                        PosixFilePermissions.fromString(
                            if (kind == ForeignLockKind.COLLISION) {
                                "rwx------"
                            } else {
                                "rwxr-xr-x"
                            },
                        ),
                    )
                    if (kind == ForeignLockKind.MALFORMED_OWNER) {
                        lifecycleLock.resolve("owner").also {
                            Files.writeString(it, "foreign\n")
                            Files.setPosixFilePermissions(
                                it,
                                PosixFilePermissions.fromString("rw-------"),
                            )
                        }
                    } else {
                        lifecycleLock.resolve("sentinel").also {
                            Files.writeString(it, "foreign\n")
                        }
                    }
                }

                ForeignLockKind.SYMLINK -> {
                    val external = repositoryRoot.resolveSibling(
                        "foreign-lock-target",
                    )
                    external.createDirectories()
                    val sentinel = external.resolve("sentinel")
                    Files.writeString(sentinel, "foreign\n")
                    Files.createSymbolicLink(lifecycleLock, external)
                    sentinel
                }
            }
        }

        fun runConcurrentDistinctRepositoryHolderAndContender():
            ConcurrentLifecycleResult {
            val peer = createDistinctRepositoryPeer()
            val paused = stateDirectory.resolve("holder-paused")
            val resume = stateDirectory.resolve("holder-resume")
            val holderLog = stateDirectory.resolve("holder.log")
            val contenderLog = stateDirectory.resolve("contender.log")
            val successorLog = stateDirectory.resolve("successor.log")
            val holderOutput = Files.createTempFile(
                temporaryDirectory,
                "holder-output-",
                ".log",
            )
            val holder = lifecycleBuilder(
                scenario = "concurrent-holder",
                arguments = emptyList(),
                extraEnvironment = emptyMap(),
                log = holderLog,
            ).redirectOutput(holderOutput.toFile()).start()

            try {
                awaitPath(paused)
                val lockIdentityBefore = pathIdentityOrNull(lifecycleLock)
                val markerBefore = readBytesOrNull(
                    lifecycleLock.resolve("owner"),
                )

                val contender = runWithLog(
                    fixture = peer,
                    scenario = "success",
                    arguments = emptyList(),
                    extraEnvironment = emptyMap(),
                    log = contenderLog,
                )
                val lockIdentityAfter = pathIdentityOrNull(lifecycleLock)
                val markerAfter = readBytesOrNull(
                    lifecycleLock.resolve("owner"),
                )
                val lockWasStable =
                    lockIdentityBefore != null &&
                        lockIdentityBefore == lockIdentityAfter &&
                        markerBefore != null &&
                        markerAfter != null &&
                        markerBefore.contentEquals(markerAfter)
                val proofWasAbsent = Files.notExists(
                    proofRoot,
                    LinkOption.NOFOLLOW_LINKS,
                ) && Files.notExists(
                    peer.proofRoot,
                    LinkOption.NOFOLLOW_LINKS,
                )

                Files.writeString(resume, "resume\n")
                val holderResult = awaitLifecycle(
                    process = holder,
                    outputFile = holderOutput,
                    log = holderLog,
                )
                val successor = runWithLog(
                    fixture = peer,
                    scenario = "success",
                    arguments = emptyList(),
                    extraEnvironment = emptyMap(),
                    log = successorLog,
                )
                return ConcurrentLifecycleResult(
                    holder = holderResult,
                    contender = contender,
                    successor = successor,
                    lockIdentityWasStableDuringContention = lockWasStable,
                    proofRootsWereAbsentDuringContention = proofWasAbsent,
                    proofRootsWereAbsentAfterSuccessor =
                        Files.notExists(
                            proofRoot,
                            LinkOption.NOFOLLOW_LINKS,
                        ) &&
                            Files.notExists(
                                peer.proofRoot,
                                LinkOption.NOFOLLOW_LINKS,
                            ),
                    repositoriesWerePhysicallyDistinct =
                        repositoryRoot.toRealPath() !=
                            peer.repositoryRoot.toRealPath(),
                )
            } finally {
                Files.writeString(resume, "resume\n")
                if (holder.isAlive) {
                    holder.destroy()
                    if (!holder.waitFor(
                            PROCESS_TERMINATION_TIMEOUT.toMillis(),
                            TimeUnit.MILLISECONDS,
                        )
                    ) {
                        holder.destroyForcibly()
                    }
                }
                Files.deleteIfExists(holderOutput)
            }
        }

        private fun createDistinctRepositoryPeer(): LifecycleFixture =
            createRepositoryFixture(
                repository = repositoryRoot.resolveSibling("repository-peer"),
                scriptContent = Files.readString(script),
                lifecycleLock = lifecycleLock,
                fakeBin = fakeBin,
                state = stateDirectory,
                temp = temporaryDirectory,
                log = stateDirectory.resolve("peer-default.log"),
            )

        private fun runWithLog(
            fixture: LifecycleFixture,
            scenario: String,
            arguments: List<String>,
            extraEnvironment: Map<String, String>,
            log: Path,
        ): LifecycleResult = fixture.runWithLog(
            scenario = scenario,
            arguments = arguments,
            extraEnvironment = extraEnvironment,
            log = log,
        )

        fun run(
            scenario: String,
            arguments: List<String> = emptyList(),
            extraEnvironment: Map<String, String> = emptyMap(),
            timeout: Duration = PROCESS_TIMEOUT,
        ): LifecycleResult = runWithLog(
            scenario = scenario,
            arguments = arguments,
            extraEnvironment = extraEnvironment,
            log = commandLog,
            timeout = timeout,
        )

        fun runFakeDocker(arguments: List<String>): ProcessResult {
            Files.deleteIfExists(commandLog)
            val outputFile = Files.createTempFile(
                temporaryDirectory,
                "fake-docker-output-",
                ".log",
            )
            val builder = ProcessBuilder(
                listOf(fakeBin.resolve("docker").toString()) + arguments,
            )
                .directory(repositoryRoot.toFile())
                .redirectErrorStream(true)
                .redirectOutput(outputFile.toFile())
            builder.environment()["DOCKER_HOST"] =
                "unix:///var/run/docker.sock"
            builder.environment()["PATH"] =
                "$fakeBin:${requireNotNull(System.getenv("PATH"))}"
            builder.environment()["TASK5_FAKE_SCENARIO"] = "success"
            builder.environment()["TASK5_FAKE_LOG"] = commandLog.toString()
            builder.environment()["TASK5_FAKE_STATE"] = stateDirectory.toString()
            builder.environment()["TASK5_FAKE_REPOSITORY"] = repositoryRoot.toString()
            builder.environment()["TASK5_FAKE_GLOBAL_LOCK"] = lifecycleLock.toString()

            val process = try {
                builder.start()
            } catch (failure: Throwable) {
                Files.deleteIfExists(outputFile)
                throw failure
            }
            try {
                val completed = process.waitFor(
                    PROCESS_TIMEOUT.toMillis(),
                    TimeUnit.MILLISECONDS,
                )
                if (!completed) process.destroyForcibly()
                assertTrue(completed, "fake Docker invocation timed out")
                return ProcessResult(
                    exitCode = process.exitValue(),
                    output = Files.readString(outputFile),
                )
            } finally {
                if (process.isAlive) process.destroyForcibly()
                Files.deleteIfExists(outputFile)
            }
        }

        fun runSignalledAfterGlobalLockMkdir(signal: String): LifecycleResult =
            runPausedAndSignalled(
                scenario = "signal-after-global-lock-mkdir",
                pausedName = "global-lock-mkdir-paused",
                resumeName = "global-lock-mkdir-resume",
                finishedName = "global-lock-mkdir-finished",
                signal = signal,
                assertPausedState = {
                    assertTrue(
                        Files.isDirectory(
                            lifecycleLock,
                            LinkOption.NOFOLLOW_LINKS,
                        ),
                        "The fake mkdir must create the global lock first",
                    )
                    assertFalse(
                        Files.exists(
                            lifecycleLock.resolve("owner"),
                            LinkOption.NOFOLLOW_LINKS,
                        ),
                        "Parent ownership publication must still be blocked",
                    )
                },
            )

        fun runSignalledDuringFailingGlobalLockMkdir(
            signal: String,
        ): LifecycleResult =
            runPausedAndSignalled(
                scenario = "signal-and-global-lock-mkdir-fails",
                pausedName = "failing-global-lock-mkdir-paused",
                resumeName = "failing-global-lock-mkdir-resume",
                finishedName = "failing-global-lock-mkdir-finished",
                signal = signal,
                assertPausedState = {
                    assertTrue(
                        Files.isDirectory(
                            lifecycleLock,
                            LinkOption.NOFOLLOW_LINKS,
                        ),
                    )
                    assertFalse(
                        Files.exists(
                            lifecycleLock.resolve("owner"),
                            LinkOption.NOFOLLOW_LINKS,
                        ),
                    )
                },
            )

        fun runSignalledAfterBaselineMktemp(signal: String): LifecycleResult =
            runPausedAndSignalled(
                scenario = "signal-after-baseline-mktemp",
                pausedName = "baseline-mktemp-paused",
                resumeName = "baseline-mktemp-resume",
                finishedName = "baseline-mktemp-finished",
                signal = signal,
                assertPausedState = {
                    assertTrue(
                        hasBaselineDirectory(),
                        "The fake mktemp must create the baseline first",
                    )
                },
            )

        fun runSignalledDuringCleanupDown(signal: String): LifecycleResult =
            runPausedAndSignalled(
                scenario = "signal-during-cleanup-down",
                pausedName = "cleanup-down-paused",
                resumeName = "cleanup-down-resume",
                finishedName = "cleanup-down-finished",
                signal = signal,
            )

        fun runSignalledDuringSuccessfulCleanupDown(
            signal: String,
        ): LifecycleResult =
            runPausedAndSignalled(
                scenario = "signal-during-successful-cleanup-down",
                pausedName = "cleanup-down-paused",
                resumeName = "cleanup-down-resume",
                finishedName = "cleanup-down-finished",
                signal = signal,
            )

        fun hasBaselineDirectory(): Boolean =
            Files.list(temporaryDirectory).use { entries ->
                entries.anyMatch {
                    it.fileName.toString().startsWith(
                        "mail-sandbox-task5-baseline.",
                    )
                }
            }

        fun hostileStartupEnvironment(): Map<String, String> {
            val bashEnvironment = stateDirectory.resolve("hostile-bash-env")
            Files.writeString(bashEnvironment, HOSTILE_BASH_ENV)
            return mapOf(
                "BASH_ENV" to bashEnvironment.toString(),
                "BASH_FUNC_stat%%" to
                    """
                    |() {
                    |  printf '%s\n' \
                    |    "injected-stat §{TASK5_LIFECYCLE_LOCK_TOKEN-} §{TASK5_PROOF_ROOT_TOKEN-} §{token-} §{actual_token-}" \
                    |    >> "§TASK5_FAKE_STARTUP_INJECTION_LOG"
                    |  "§TASK5_FAKE_REAL_STAT" "§@"
                    |}
                    """.trimMargin().replace('§', '$'),
                "BASH_FUNC_docker%%" to
                    """
                    |() {
                    |  printf '%s\n' \
                    |    "injected-docker §{DOCKER_HOST-unset}" \
                    |    >> "§TASK5_FAKE_STARTUP_INJECTION_LOG"
                    |  "§TASK5_FAKE_REAL_DOCKER" "§@"
                    |}
                    """.trimMargin().replace('§', '$'),
                "TASK5_FAKE_STARTUP_INJECTION_LOG" to
                    stateDirectory.resolve("startup-injection.log").toString(),
                "TASK5_FAKE_REAL_STAT" to fakeBin.resolve("stat").toString(),
                "TASK5_FAKE_REAL_DOCKER" to fakeBin.resolve("docker").toString(),
            )
        }

        fun startupInjectionTranscript(): String {
            val log = stateDirectory.resolve("startup-injection.log")
            return if (Files.exists(log)) Files.readString(log) else ""
        }

        fun runExactForgedCleanStageWithInvalidTmpdir(): LifecycleResult {
            Files.deleteIfExists(commandLog)
            val outputFile = Files.createTempFile(
                temporaryDirectory,
                "forged-clean-stage-output-",
                ".log",
            )
            val builder = ProcessBuilder(script.toString())
                .directory(repositoryRoot.toFile())
                .redirectErrorStream(true)
                .redirectOutput(outputFile.toFile())
            val environment = builder.environment()
            environment.clear()
            environment["HOME"] = repositoryRoot.toString()
            environment["TMPDIR"] = "relative-task5-tmp"
            environment["PATH"] = "$fakeBin:$PRODUCTION_TRUSTED_PATH"
            environment["TASK5_CLEAN_STAGE"] = "1"
            environment["TASK5_FAKE_GLOBAL_LOCK"] = lifecycleLock.toString()
            environment["TASK5_FAKE_LOG"] = commandLog.toString()
            environment["TASK5_FAKE_REPOSITORY"] = repositoryRoot.toString()
            environment["TASK5_FAKE_SCENARIO"] = "success"
            environment["TASK5_FAKE_STATE"] = stateDirectory.toString()
            val process = try {
                builder.start()
            } catch (failure: Throwable) {
                Files.deleteIfExists(outputFile)
                throw failure
            }
            return awaitLifecycle(
                process = process,
                outputFile = outputFile,
                log = commandLog,
            )
        }

        private fun runPausedAndSignalled(
            scenario: String,
            pausedName: String,
            resumeName: String,
            finishedName: String,
            signal: String,
            assertPausedState: () -> Unit = {},
        ): LifecycleResult {
            val paused = stateDirectory.resolve(pausedName)
            val resume = stateDirectory.resolve(resumeName)
            val finished = stateDirectory.resolve(finishedName)
            val outputFile = Files.createTempFile(
                temporaryDirectory,
                "signalled-lifecycle-output-",
                ".log",
            )
            val process = lifecycleBuilder(
                scenario = scenario,
                arguments = emptyList(),
                extraEnvironment = emptyMap(),
                log = commandLog,
                isolatedProcessGroup = true,
            ).redirectOutput(outputFile.toFile()).start()

            try {
                awaitPath(paused)
                assertPausedState()
                sendSignal(process, signal, processGroup = true)
                Files.writeString(resume, "resume\n")
                val result = awaitLifecycle(
                    process = process,
                    outputFile = outputFile,
                    log = commandLog,
                )
                assertTrue(
                    Files.exists(finished, LinkOption.NOFOLLOW_LINKS),
                    "The paused child did not survive process-group $signal",
                )
                return result
            } finally {
                Files.writeString(resume, "resume\n")
                if (process.isAlive) {
                    process.destroyForcibly()
                    process.waitFor(
                        PROCESS_TERMINATION_TIMEOUT.toMillis(),
                        TimeUnit.MILLISECONDS,
                    )
                }
                Files.deleteIfExists(outputFile)
            }
        }

        private fun sendSignal(
            process: Process,
            signal: String,
            processGroup: Boolean = false,
        ) {
            val sender = ProcessBuilder(
                "/bin/kill",
                "-s",
                signal,
                "--",
                if (processGroup) {
                    "-${process.pid()}"
                } else {
                    process.pid().toString()
                },
            ).start()
            assertTrue(
                sender.waitFor(
                    PROCESS_TERMINATION_TIMEOUT.toMillis(),
                    TimeUnit.MILLISECONDS,
                ),
                "Timed out sending $signal to lifecycle process",
            )
            assertEquals(
                0,
                sender.exitValue(),
                "Could not send $signal to lifecycle process",
            )
        }

        private fun runWithLog(
            scenario: String,
            arguments: List<String>,
            extraEnvironment: Map<String, String>,
            log: Path,
            timeout: Duration = PROCESS_TIMEOUT,
        ): LifecycleResult {
            val builder = lifecycleBuilder(
                scenario = scenario,
                arguments = arguments,
                extraEnvironment = extraEnvironment,
                log = log,
            )
            val outputFile = Files.createTempFile(
                temporaryDirectory,
                "lifecycle-output-",
                ".log",
            )
            val process = try {
                builder
                    .redirectOutput(outputFile.toFile())
                    .start()
            } catch (failure: Throwable) {
                Files.deleteIfExists(outputFile)
                throw failure
            }
            return awaitLifecycle(
                process = process,
                outputFile = outputFile,
                log = log,
                timeout = timeout,
            )
        }

        private fun lifecycleBuilder(
            scenario: String,
            arguments: List<String>,
            extraEnvironment: Map<String, String>,
            log: Path,
            isolatedProcessGroup: Boolean = false,
        ): ProcessBuilder {
            Files.deleteIfExists(log)
            val directCommand = listOf(script.toString()) + arguments
            val command = if (isolatedProcessGroup) {
                listOf(
                    "/usr/bin/python3",
                    "-c",
                    "import os,sys; os.setsid(); " +
                        "os.execv(sys.argv[1], sys.argv[1:])",
                ) + directCommand
            } else {
                directCommand
            }
            val builder = ProcessBuilder(command)
                .directory(repositoryRoot.toFile())
                .redirectErrorStream(true)
            val environment = builder.environment()
            environment.keys
                .filter {
                    it.startsWith("DOVECOT_") ||
                        it.startsWith("COMPOSE_") ||
                        it.startsWith("DOCKER_")
                }
                .toList()
                .forEach(environment::remove)
            environment["PATH"] =
                "$fakeBin:${requireNotNull(System.getenv("PATH"))}"
            environment["TMPDIR"] = temporaryDirectory.toString()
            environment["TASK5_FAKE_SCENARIO"] = scenario
            environment["TASK5_FAKE_LOG"] = log.toString()
            environment["TASK5_FAKE_STATE"] = stateDirectory.toString()
            environment["TASK5_FAKE_REPOSITORY"] = repositoryRoot.toString()
            environment["TASK5_FAKE_GLOBAL_LOCK"] = lifecycleLock.toString()
            environment.putAll(extraEnvironment)
            return builder
        }

        private fun awaitLifecycle(
            process: Process,
            outputFile: Path,
            log: Path,
            timeout: Duration = PROCESS_TIMEOUT,
        ): LifecycleResult {
            try {
                val completed = process.waitFor(
                    timeout.toMillis(),
                    TimeUnit.MILLISECONDS,
                )
                if (!completed) {
                    process.destroy()
                    if (!process.waitFor(
                            PROCESS_TERMINATION_TIMEOUT.toMillis(),
                            TimeUnit.MILLISECONDS,
                        )
                    ) {
                        process.destroyForcibly()
                        process.waitFor(
                            PROCESS_TERMINATION_TIMEOUT.toMillis(),
                            TimeUnit.MILLISECONDS,
                        )
                    }
                }
                val output = Files.readString(outputFile)
                assertTrue(completed, "Lifecycle script timed out\n$output")
                return LifecycleResult(
                    exitCode = process.exitValue(),
                    output = output,
                    commands = if (Files.exists(log)) {
                        Files.readAllLines(log)
                    } else {
                        emptyList()
                    },
                )
            } finally {
                if (process.isAlive) process.destroyForcibly()
                Files.deleteIfExists(outputFile)
            }
        }

        private fun awaitPath(path: Path) {
            val deadline = System.nanoTime() + PROCESS_TIMEOUT.toNanos()
            while (Files.notExists(path, LinkOption.NOFOLLOW_LINKS)) {
                assertTrue(
                    System.nanoTime() < deadline,
                    "Timed out waiting for $path",
                )
                Thread.sleep(20)
            }
        }

        private fun pathIdentityOrNull(path: Path): Any? =
            runCatching {
                Files.readAttributes(
                    path,
                    BasicFileAttributes::class.java,
                    LinkOption.NOFOLLOW_LINKS,
                ).fileKey()
            }.getOrNull()

        private fun readBytesOrNull(path: Path): ByteArray? =
            runCatching { Files.readAllBytes(path) }.getOrNull()

        companion object {
            fun create(sandbox: Path, sourceScript: Path): LifecycleFixture {
                assertTrue(
                    Files.isRegularFile(sourceScript),
                    "Task 5 proof lifecycle script is missing",
                )
                val repository = sandbox.resolve("repository")
                val fakeBin = sandbox.resolve("fake-bin")
                val state = sandbox.resolve("state")
                val temp = sandbox.resolve("tmp")
                val sharedLockParent = sandbox.resolve("global-lock-parent")
                val sharedLifecycleLock = sharedLockParent.resolve(
                    "mail-sandbox-task5-proof.lifecycle.lock",
                )
                fakeBin.createDirectories()
                state.createDirectories()
                temp.createDirectories()
                sharedLockParent.createDirectories()
                val log = sandbox.resolve("commands.log")
                writeExecutable(fakeBin.resolve("docker"), FAKE_DOCKER)
                writeExecutable(fakeBin.resolve("install"), FAKE_INSTALL)
                writeExecutable(fakeBin.resolve("mkdir"), FAKE_MKDIR)
                writeExecutable(fakeBin.resolve("mktemp"), FAKE_MKTEMP)
                writeExecutable(fakeBin.resolve("lsof"), FAKE_LSOF)
                writeExecutable(fakeBin.resolve("openssl"), FAKE_OPENSSL)
                writeExecutable(fakeBin.resolve("python3"), FAKE_PYTHON)
                writeExecutable(fakeBin.resolve("stat"), FAKE_STAT)
                writeExecutable(
                    fakeBin.resolve("task5-child-env-guard"),
                    FAKE_CHILD_ENV_GUARD,
                )
                val productionSource = Files.readString(sourceScript)
                val productionLockOccurrences = productionSource
                    .windowed(PRODUCTION_LIFECYCLE_LOCK.length)
                    .count { it == PRODUCTION_LIFECYCLE_LOCK }
                assertEquals(
                    1,
                    productionLockOccurrences,
                    "Fixture must patch exactly one production lock literal",
                )
                assertEquals(
                    1,
                    productionSource
                        .windowed(PRODUCTION_TRUSTED_PATH.length)
                        .count { it == PRODUCTION_TRUSTED_PATH },
                    "Fixture must patch exactly one trusted PATH literal",
                )
                val cleanHandoffOccurrences = productionSource
                    .windowed(PRODUCTION_CLEAN_HANDOFF.length)
                    .count { it == PRODUCTION_CLEAN_HANDOFF }
                assertEquals(
                    1,
                    cleanHandoffOccurrences,
                    "Fixture must patch exactly one clean environment handoff",
                )
                val cleanAllowlistOccurrences = productionSource
                    .windowed(PRODUCTION_CLEAN_ALLOWLIST.length)
                    .count { it == PRODUCTION_CLEAN_ALLOWLIST }
                assertEquals(
                    1,
                    cleanAllowlistOccurrences,
                    "Fixture must patch exactly one clean environment allowlist",
                )
                val scriptContent = productionSource.replace(
                    PRODUCTION_LIFECYCLE_LOCK,
                    sharedLifecycleLock.toString(),
                ).replace(
                    PRODUCTION_TRUSTED_PATH,
                    "$fakeBin:$PRODUCTION_TRUSTED_PATH",
                ).replace(
                    PRODUCTION_CLEAN_HANDOFF,
                    FIXTURE_CLEAN_HANDOFF,
                ).replace(
                    PRODUCTION_CLEAN_ALLOWLIST,
                    FIXTURE_CLEAN_ALLOWLIST,
                )

                return createRepositoryFixture(
                    repository = repository,
                    scriptContent = scriptContent,
                    lifecycleLock = sharedLifecycleLock,
                    fakeBin = fakeBin,
                    state = state,
                    temp = temp,
                    log = log,
                )
            }

            private fun createRepositoryFixture(
                repository: Path,
                scriptContent: String,
                lifecycleLock: Path,
                fakeBin: Path,
                state: Path,
                temp: Path,
                log: Path,
            ): LifecycleFixture {
                val resourceDirectory = repository.resolve(
                    "debug-dashboard/dashboard-server/testResources/" +
                        "dovecot-gate0c",
                )
                resourceDirectory.createDirectories()
                repository.resolve("debug-dashboard/.runtime").createDirectories()
                Files.writeString(repository.resolve("docker-compose.yml"), "services: {}\n")
                Files.writeString(
                    repository.resolve("debug-dashboard/project.yaml"),
                    "modules: [dashboard-server]\n",
                )
                Files.writeString(
                    resourceDirectory.resolve("compose.task5-proof.yml"),
                    "services: {}\n",
                )
                Files.writeString(
                    resourceDirectory.resolve("network-isolation-check.py"),
                    "# fixed test fixture\n",
                )
                Files.writeString(
                    resourceDirectory.resolve(
                        "test_network_isolation_check.py",
                    ),
                    "# fixed test fixture\n",
                )
                val script = resourceDirectory.resolve("run-task5-proof.sh")
                Files.writeString(script, scriptContent)
                makeExecutable(script)
                writeExecutable(
                    repository.resolve("debug-dashboard/kotlin"),
                    FAKE_KOTLIN,
                )

                return LifecycleFixture(
                    repositoryRoot = repository,
                    script = script,
                    proofRoot = repository.resolve(
                        "debug-dashboard/.runtime/task5-proof",
                    ),
                    runtimeRoot = repository.resolve("debug-dashboard/.runtime"),
                    fakeBin = fakeBin,
                    commandLog = log,
                    stateDirectory = state,
                    temporaryDirectory = temp,
                    lifecycleLock = lifecycleLock,
                )
            }

            private fun writeExecutable(path: Path, content: String) {
                Files.writeString(path, content)
                makeExecutable(path)
            }

            private fun makeExecutable(path: Path) {
                Files.setPosixFilePermissions(
                    path,
                    PosixFilePermissions.fromString("rwx------"),
                )
            }
        }
    }

    companion object {
        private val PROCESS_TIMEOUT = Duration.ofSeconds(15)
        private val CHILD_ENV_GUARD_PROCESS_TIMEOUT = Duration.ofSeconds(20)
        private val PROCESS_TERMINATION_TIMEOUT = Duration.ofSeconds(1)
        private const val PRODUCTION_LIFECYCLE_LOCK =
            "/private/tmp/mail-sandbox-task5-proof.lifecycle.lock"
        private const val PRODUCTION_TRUSTED_PATH =
            "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
        private val PRODUCTION_CLEAN_HANDOFF = """
            |    TASK5_CLEAN_STAGE=1 \
            |    /bin/bash --noprofile --norc -p "§0"
        """.trimMargin().replace('§', '$')
        private val FIXTURE_CLEAN_HANDOFF = """
            |    TASK5_CLEAN_STAGE=1 \
            |    TASK5_FAKE_COLLISION_NAME="§{TASK5_FAKE_COLLISION_NAME-}" \
            |    TASK5_FAKE_GLOBAL_LOCK="§{TASK5_FAKE_GLOBAL_LOCK-}" \
            |    TASK5_FAKE_GUARD_CHILD_ENV="§{TASK5_FAKE_GUARD_CHILD_ENV-}" \
            |    TASK5_FAKE_LOG="§{TASK5_FAKE_LOG-}" \
            |    TASK5_FAKE_REPOSITORY="§{TASK5_FAKE_REPOSITORY-}" \
            |    TASK5_FAKE_SCENARIO="§{TASK5_FAKE_SCENARIO-}" \
            |    TASK5_FAKE_STATE="§{TASK5_FAKE_STATE-}" \
            |    /bin/bash --noprofile --norc -p "§0"
        """.trimMargin().replace('§', '$')
        private const val PRODUCTION_CLEAN_ALLOWLIST =
            "HOME | PATH | PWD | SHLVL | TASK5_CLEAN_STAGE | TMPDIR | _)"
        private const val FIXTURE_CLEAN_ALLOWLIST =
            "HOME | PATH | PWD | SHLVL | TASK5_CLEAN_STAGE | TMPDIR | " +
                "TASK5_FAKE_COLLISION_NAME | TASK5_FAKE_GLOBAL_LOCK | " +
                "TASK5_FAKE_GUARD_CHILD_ENV | TASK5_FAKE_LOG | " +
                "TASK5_FAKE_REPOSITORY | TASK5_FAKE_SCENARIO | " +
                "TASK5_FAKE_STATE | _)"
        private val LOCK_TOKEN_CANARY = "0".repeat(63) + "1"
        private val ROOT_TOKEN_CANARY = "0".repeat(47) + "2"
        private const val FIXED_DOCKER_HOST_LOG =
            "docker-host unix:///var/run/docker.sock"
        private const val UNSET_PROOF_ENVIRONMENT =
            "proof-env unset unset unset unset unset"
        private const val FIXED_PROOF_ENVIRONMENT =
            "proof-env 1 task5-proof mail-sandbox-task5-proof " +
                "docker-compose.yml:debug-dashboard/dashboard-server/" +
                "testResources/dovecot-gate0c/compose.task5-proof.yml 1"
        private const val HEALTH_INSPECT_FORMAT =
            "{{.Id}} {{.State.StartedAt}} {{.State.Status}} " +
                "{{with (index .State \"Health\")}}{{.Status}}" +
                "{{else}}none{{end}} {{.RestartCount}}"
        private const val DOVECOT_GATE_PACKAGE =
            "mail.sandbox.dashboard.server.gate.dovecot"
        private val TASK7_NON_LIVE_CLASSES = listOf(
            "DovecotOperatorConfigTest",
            "DovecotAuthenticationResponseClassifierTest",
            "DovecotIsolationMailboxContractTest",
            "DovecotOperatorCredentialStoreTest",
            "DovecotOperatorProcessTransportTest",
            "DovecotOperatorApplicationLeaseRegistryTest",
            "DovecotOperatorBoundedExchangeTest",
            "DovecotTask6TopologyProofTest",
            "DovecotTask6OperatorProcessInventoryTest",
            "DovecotTask6ProcessProofTest",
            "DovecotOperatorExecTransportLiveTest",
            "DovecotTask5ProofLifecycleTest",
        )
        private val FIXED_PROOF_RESOURCE_NAMES = listOf(
            "mail-sandbox-task5-proof-dovecot-1",
            "mail-sandbox-task5-proof-dovecot-operator-1",
            "mail-sandbox-task5-proof-postfix-1",
            "mail-sandbox-task5-proof-oauth2-mock-1",
            "mail-sandbox-task5-proof_default",
            "mail-sandbox-task5-proof_operator-ingress",
            "mail-sandbox-task5-proof_task5-proof-vmail",
            "mail-sandbox-task5-proof_task5-proof-logs",
        )

        private fun runProcess(
            command: List<String>,
            workingDirectory: Path,
        ): ProcessResult {
            val outputFile = Files.createTempFile(
                "task5-proof-process-output-",
                ".log",
            )
            val process = try {
                ProcessBuilder(command)
                    .directory(workingDirectory.toFile())
                    .redirectErrorStream(true)
                    .redirectOutput(outputFile.toFile())
                    .start()
            } catch (failure: Throwable) {
                Files.deleteIfExists(outputFile)
                throw failure
            }
            try {
                val completed = process.waitFor(
                    PROCESS_TIMEOUT.toMillis(),
                    TimeUnit.MILLISECONDS,
                )
                if (!completed) {
                    process.destroy()
                    if (!process.waitFor(
                            PROCESS_TERMINATION_TIMEOUT.toMillis(),
                            TimeUnit.MILLISECONDS,
                        )
                    ) {
                        process.destroyForcibly()
                        process.waitFor(
                            PROCESS_TERMINATION_TIMEOUT.toMillis(),
                            TimeUnit.MILLISECONDS,
                        )
                    }
                }
                val output = Files.readString(outputFile)
                assertTrue(
                    completed,
                    "Process timed out: ${command.joinToString(" ")}\n$output",
                )
                return ProcessResult(process.exitValue(), output)
            } finally {
                if (process.isAlive) process.destroyForcibly()
                Files.deleteIfExists(outputFile)
            }
        }

        private val FAKE_DOCKER = """
            |#!/bin/sh
            |set -eu
            |if [ "§{TASK5_FAKE_GUARD_CHILD_ENV:-0}" = 1 ]; then
            |  task5-child-env-guard docker
            |fi
            |if [ "§TASK5_FAKE_SCENARIO" = concurrent-holder ] &&
            |  [ ! -f "§TASK5_FAKE_STATE/holder-pause-issued" ]; then
            |  : > "§TASK5_FAKE_STATE/holder-pause-issued"
            |  : > "§TASK5_FAKE_STATE/holder-paused"
            |  while [ ! -f "§TASK5_FAKE_STATE/holder-resume" ]; do
            |    sleep 0.05
            |  done
            |fi
            |printf '%s\n' "docker-host §{DOCKER_HOST:-unset}" >> "§TASK5_FAKE_LOG"
            |[ "§{DOCKER_HOST:-unset}" = "unix:///var/run/docker.sock" ] ||
            |  exit 63
            |printf '%s\n' "docker §*" >> "§TASK5_FAKE_LOG"
            |baseline_dovecot_id=1111111111111111111111111111111111111111111111111111111111111111
            |baseline_postfix_id=2222222222222222222222222222222222222222222222222222222222222222
            |baseline_oauth2_id=3333333333333333333333333333333333333333333333333333333333333333
            |health_inspect_format='{{.Id}} {{.State.StartedAt}} {{.State.Status}} {{with (index .State "Health")}}{{.Status}}{{else}}none{{end}} {{.RestartCount}}'
            |case "§*" in
            |  "ps --all --quiet --filter label=com.docker.compose.project=mail-sandbox-task5-proof")
            |    if [ "§TASK5_FAKE_SCENARIO" = labeled-resource-collision ]; then
            |      printf '%s\n' labeled-proof-container
            |    fi
            |    ;;
            |  "volume ls --quiet --filter label=com.docker.compose.project=mail-sandbox-task5-proof")
            |    ;;
            |  "network ls --quiet --filter label=com.docker.compose.project=mail-sandbox-task5-proof")
            |    if [ "§TASK5_FAKE_SCENARIO" = initial-network-query-fails ]; then
            |      exit 11
            |    fi
            |    ;;
            |  "ps --all --quiet --filter name=^/mail-sandbox-task5-proof-dovecot-1§"|\
            |  "ps --all --quiet --filter name=^/mail-sandbox-task5-proof-dovecot-operator-1§"|\
            |  "ps --all --quiet --filter name=^/mail-sandbox-task5-proof-postfix-1§"|\
            |  "ps --all --quiet --filter name=^/mail-sandbox-task5-proof-oauth2-mock-1§")
            |    if [ "§TASK5_FAKE_SCENARIO" = full-container-query-fails ]; then
            |      exit 14
            |    fi
            |    case "§*" in
            |      *"§{TASK5_FAKE_COLLISION_NAME:-}§")
            |        if [ -n "§{TASK5_FAKE_COLLISION_NAME:-}" ]; then
            |          printf '%s\n' fixed-name-container-id
            |          printf '%s\n' "fake-name-output §TASK5_FAKE_COLLISION_NAME" >> "§TASK5_FAKE_LOG"
            |        fi
            |        ;;
            |    esac
            |    ;;
            |  "network ls --quiet --filter name=^mail-sandbox-task5-proof_default§"|\
            |  "network ls --quiet --filter name=^mail-sandbox-task5-proof_operator-ingress§")
            |    if [ "§TASK5_FAKE_SCENARIO" = full-network-query-fails ]; then
            |      exit 15
            |    fi
            |    case "§*" in
            |      *"§{TASK5_FAKE_COLLISION_NAME:-}§")
            |        if [ -n "§{TASK5_FAKE_COLLISION_NAME:-}" ]; then
            |          printf '%s\n' fixed-name-network-id
            |          printf '%s\n' "fake-name-output §TASK5_FAKE_COLLISION_NAME" >> "§TASK5_FAKE_LOG"
            |        fi
            |        ;;
            |    esac
            |    if [ "§TASK5_FAKE_SCENARIO" = cleanup-exact-network-remains ] &&
            |      [ -f "§TASK5_FAKE_STATE/down-seen" ] &&
            |      [ "§*" = "network ls --quiet --filter name=^mail-sandbox-task5-proof_operator-ingress§" ]; then
            |      printf '%s\n' fixed-name-network-id
            |      printf '%s\n' "fake-name-output mail-sandbox-task5-proof_operator-ingress" >> "§TASK5_FAKE_LOG"
            |    fi
            |    ;;
            |  "volume ls --quiet --filter name=^mail-sandbox-task5-proof_task5-proof-vmail§"|\
            |  "volume ls --quiet --filter name=^mail-sandbox-task5-proof_task5-proof-logs§")
            |    if [ "§TASK5_FAKE_SCENARIO" = full-volume-query-fails ]; then
            |      exit 16
            |    fi
            |    case "§*" in
            |      *"§{TASK5_FAKE_COLLISION_NAME:-}§")
            |        if [ -n "§{TASK5_FAKE_COLLISION_NAME:-}" ]; then
            |          printf '%s\n' fixed-name-volume-id
            |          printf '%s\n' "fake-name-output §TASK5_FAKE_COLLISION_NAME" >> "§TASK5_FAKE_LOG"
            |        fi
            |        ;;
            |    esac
            |    if [ "§TASK5_FAKE_SCENARIO" = cleanup-exact-volume-remains ] &&
            |      [ -f "§TASK5_FAKE_STATE/down-seen" ] &&
            |      [ "§*" = "volume ls --quiet --filter name=^mail-sandbox-task5-proof_task5-proof-logs§" ]; then
            |      printf '%s\n' fixed-name-volume-id
            |      printf '%s\n' "fake-name-output mail-sandbox-task5-proof_task5-proof-logs" >> "§TASK5_FAKE_LOG"
            |    fi
            |    ;;
            |  "ps --all --quiet --no-trunc --filter label=com.docker.compose.project=dovecot-docker --filter label=com.docker.compose.service=dovecot")
            |    if [ -f "§TASK5_FAKE_STATE/down-seen" ]; then
            |      if [ "§TASK5_FAKE_SCENARIO" = postflight-list-fails ]; then
            |        exit 17
            |      fi
            |      if [ "§TASK5_FAKE_SCENARIO" = postflight-id-changes ]; then
            |        printf '%s\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
            |        exit 0
            |      fi
            |    fi
            |    printf '%s\n' "§baseline_dovecot_id"
            |    ;;
            |  "ps --all --quiet --no-trunc --filter label=com.docker.compose.project=dovecot-docker --filter label=com.docker.compose.service=postfix")
            |    if [ "§TASK5_FAKE_SCENARIO" = baseline-ps-fails ]; then
            |      exit 12
            |    fi
            |    printf '%s\n' "§baseline_postfix_id"
            |    ;;
            |  "ps --all --quiet --no-trunc --filter label=com.docker.compose.project=dovecot-docker --filter label=com.docker.compose.service=oauth2-mock")
            |    printf '%s\n' "§baseline_oauth2_id"
            |    ;;
            |  inspect*)
            |    if [ "§#" -ne 4 ] ||
            |      [ "§1" != inspect ] ||
            |      [ "§2" != --format ] ||
            |      [ "§3" != "§health_inspect_format" ]; then
            |      printf '%s\n' "forbidden-docker-access §*" >> "§TASK5_FAKE_LOG"
            |      exit 88
            |    fi
            |    last_argument=§4
            |    case "§last_argument" in
            |      "§baseline_dovecot_id"|"§baseline_postfix_id"|"§baseline_oauth2_id") ;;
            |      *)
            |        printf '%s\n' "forbidden-docker-access §*" >> "§TASK5_FAKE_LOG"
            |        exit 88
            |        ;;
            |    esac
            |    if [ "§TASK5_FAKE_SCENARIO" = baseline-inspect-fails ] &&
            |      [ "§last_argument" = "§baseline_postfix_id" ]; then
            |      exit 13
            |    fi
            |    if [ -f "§TASK5_FAKE_STATE/down-seen" ]; then
            |      if [ "§TASK5_FAKE_SCENARIO" = postflight-inspect-fails ] &&
            |        [ "§last_argument" = "§baseline_dovecot_id" ]; then
            |        exit 18
            |      fi
            |      if [ "§TASK5_FAKE_SCENARIO" = postflight-state-changes ] &&
            |        [ "§last_argument" = "§baseline_dovecot_id" ]; then
            |        printf '%s\n' "§last_argument 2026-07-29T00:00:01Z exited none 1"
            |        exit 0
            |      fi
            |    fi
            |    printf '%s\n' "§last_argument 2026-07-29T00:00:00Z running none 0"
            |    ;;
            |  "compose --file docker-compose.yml config --quiet oauth2-mock dovecot postfix"|\
            |  "compose --project-name mail-sandbox-task5-proof --file docker-compose.yml --file debug-dashboard/dashboard-server/testResources/dovecot-gate0c/compose.task5-proof.yml config --quiet oauth2-mock dovecot postfix dovecot-operator"|\
            |  "compose --project-name mail-sandbox-task5-proof --file docker-compose.yml --file debug-dashboard/dashboard-server/testResources/dovecot-gate0c/compose.task5-proof.yml up --detach --build --force-recreate --wait oauth2-mock dovecot postfix"|\
            |  "compose --project-name mail-sandbox-task5-proof --file docker-compose.yml --file debug-dashboard/dashboard-server/testResources/dovecot-gate0c/compose.task5-proof.yml --profile dovecot-operator up --detach --build --force-recreate --no-deps --wait dovecot-operator"|\
            |  "compose --project-name mail-sandbox-task5-proof --file docker-compose.yml --file debug-dashboard/dashboard-server/testResources/dovecot-gate0c/compose.task5-proof.yml --profile dovecot-operator ps oauth2-mock dovecot postfix dovecot-operator")
            |    ;;
            |  "compose --file docker-compose.yml --profile dovecot-operator config --format json oauth2-mock dovecot postfix dovecot-operator"|\
            |  "compose --project-name mail-sandbox-task5-proof --file docker-compose.yml --file debug-dashboard/dashboard-server/testResources/dovecot-gate0c/compose.task5-proof.yml config --format json oauth2-mock dovecot postfix dovecot-operator")
            |    printf '%s\n' '{}'
            |    ;;
            |  "compose --project-name mail-sandbox-task5-proof --file docker-compose.yml --file debug-dashboard/dashboard-server/testResources/dovecot-gate0c/compose.task5-proof.yml exec -T dovecot dovecot --version")
            |    if [ "§TASK5_FAKE_SCENARIO" = provider-version-mismatch ]; then
            |      printf '%s\n' '2.4.3 (wrong)'
            |    else
            |      printf '%s\n' '2.4.4 (8b687aa65c)'
            |    fi
            |    ;;
            |  "compose --project-name mail-sandbox-task5-proof --file docker-compose.yml --file debug-dashboard/dashboard-server/testResources/dovecot-gate0c/compose.task5-proof.yml exec -T oauth2-mock python --version")
            |    printf '%s\n' 'Python 3.14.6'
            |    ;;
            |  "compose --project-name mail-sandbox-task5-proof --file docker-compose.yml --file debug-dashboard/dashboard-server/testResources/dovecot-gate0c/compose.task5-proof.yml exec -T postfix postconf -h mail_version")
            |    printf '%s\n' '3.10.12'
            |    ;;
            |  "compose --project-name mail-sandbox-task5-proof --file docker-compose.yml --file debug-dashboard/dashboard-server/testResources/dovecot-gate0c/compose.task5-proof.yml exec -T postfix postconf -h compatibility_level")
            |    printf '%s\n' '3.6'
            |    ;;
            |  'compose --project-name mail-sandbox-task5-proof --file docker-compose.yml --file debug-dashboard/dashboard-server/testResources/dovecot-gate0c/compose.task5-proof.yml exec -T postfix dpkg-query -W -f=§{Package}=§{Version}\n postfix')
            |    printf '%s\n' 'postfix=3.10.12-0+deb13u2'
            |    ;;
            |  'compose --project-name mail-sandbox-task5-proof --file docker-compose.yml --file debug-dashboard/dashboard-server/testResources/dovecot-gate0c/compose.task5-proof.yml exec -T postfix dpkg-query -W -f=§{Package}=§{Version}\n libsasl2-2')
            |    printf '%s\n' 'libsasl2-2=2.1.28+dfsg1-9'
            |    ;;
            |  'compose --project-name mail-sandbox-task5-proof --file docker-compose.yml --file debug-dashboard/dashboard-server/testResources/dovecot-gate0c/compose.task5-proof.yml exec -T postfix dpkg-query -W -f=§{Package}=§{Version}\n libsasl2-modules')
            |    printf '%s\n' 'libsasl2-modules=2.1.28+dfsg1-9'
            |    ;;
            |  'compose --project-name mail-sandbox-task5-proof --file docker-compose.yml --file debug-dashboard/dashboard-server/testResources/dovecot-gate0c/compose.task5-proof.yml exec -T postfix dpkg-query -W -f=§{Package}=§{Version}\n sasl2-bin')
            |    printf '%s\n' 'sasl2-bin=2.1.28+dfsg1-9'
            |    ;;
            |  'compose --project-name mail-sandbox-task5-proof --file docker-compose.yml --file debug-dashboard/dashboard-server/testResources/dovecot-gate0c/compose.task5-proof.yml exec -T postfix dpkg-query -W -f=§{Package}=§{Version}\n netcat-openbsd')
            |    printf '%s\n' 'netcat-openbsd=1.229-1'
            |    ;;
            |  "compose --project-name mail-sandbox-task5-proof --file docker-compose.yml --file debug-dashboard/dashboard-server/testResources/dovecot-gate0c/compose.task5-proof.yml exec -T dovecot /dovecot/bin/doveconf -n")
            |    printf '%s\n' 'dovecot_config_version = 2.4.4'
            |    ;;
            |  "compose --project-name mail-sandbox-task5-proof --file docker-compose.yml --file debug-dashboard/dashboard-server/testResources/dovecot-gate0c/compose.task5-proof.yml exec -T dovecot-operator /dovecot/bin/doveconf -n")
            |    printf '%s\n' 'dovecot_config_version = 2.4.4'
            |    ;;
            |  "compose --project-name mail-sandbox-task5-proof --file docker-compose.yml --file debug-dashboard/dashboard-server/testResources/dovecot-gate0c/compose.task5-proof.yml exec -T dovecot-operator /usr/local/bin/operator-healthcheck")
            |    ;;
            |  "compose --project-name mail-sandbox-task5-proof --file docker-compose.yml --file debug-dashboard/dashboard-server/testResources/dovecot-gate0c/compose.task5-proof.yml down --volumes --remove-orphans")
            |    if [ "§TASK5_FAKE_SCENARIO" = signal-during-cleanup-down ] ||
            |      [ "§TASK5_FAKE_SCENARIO" = signal-during-successful-cleanup-down ]; then
            |      /usr/bin/python3 -c '
            |import os
            |import signal
            |import sys
            |import time
            |state = sys.argv[1]
            |signal.signal(signal.SIGINT, signal.SIG_DFL)
            |signal.signal(signal.SIGTERM, signal.SIG_DFL)
            |open(os.path.join(state, "cleanup-down-paused"), "w").close()
            |while not os.path.exists(os.path.join(state, "cleanup-down-resume")):
            |    time.sleep(0.05)
            |open(os.path.join(state, "cleanup-down-finished"), "w").close()
            |' "§TASK5_FAKE_STATE"
            |    fi
            |    : > "§TASK5_FAKE_STATE/down-seen"
            |    if [ "§TASK5_FAKE_SCENARIO" = down-fails ] ||
            |      [ "§TASK5_FAKE_SCENARIO" = main-and-down-fail ]; then
            |      exit 42
            |    fi
            |    ;;
            |  *)
            |    printf '%s\n' "forbidden-docker-access §*" >> "§TASK5_FAKE_LOG"
            |    exit 88
            |    ;;
            |esac
            |exit 0
            |
        """.trimMargin().replace('§', '$')

        private val FAKE_MKDIR = """
            |#!/bin/sh
            |set -eu
            |if [ "§{TASK5_FAKE_GUARD_CHILD_ENV:-0}" = 1 ]; then
            |  task5-child-env-guard mkdir
            |fi
            |printf '%s\n' "mkdir §*" >> "§TASK5_FAKE_LOG"
            |root="§TASK5_FAKE_REPOSITORY/debug-dashboard/.runtime/task5-proof"
            |if [ "§*" = "-m 700 §TASK5_FAKE_GLOBAL_LOCK" ]; then
            |  case "§TASK5_FAKE_SCENARIO" in
            |    signal-after-global-lock-mkdir)
            |      /bin/mkdir "§@"
            |      : > "§TASK5_FAKE_STATE/global-lock-mkdir-paused"
            |      while [ ! -f "§TASK5_FAKE_STATE/global-lock-mkdir-resume" ]; do
            |        sleep 0.05
            |      done
            |      : > "§TASK5_FAKE_STATE/global-lock-mkdir-finished"
            |      exit 0
            |      ;;
            |    signal-and-global-lock-mkdir-fails)
            |      /bin/mkdir "§@"
            |      : > "§TASK5_FAKE_STATE/failing-global-lock-mkdir-paused"
            |      while [ ! -f "§TASK5_FAKE_STATE/failing-global-lock-mkdir-resume" ]; do
            |        sleep 0.05
            |      done
            |      : > "§TASK5_FAKE_STATE/failing-global-lock-mkdir-finished"
            |      exit 75
            |      ;;
            |    global-lock-mkdir-created-then-fails)
            |      /bin/mkdir "§@"
            |      exit 74
            |      ;;
            |  esac
            |fi
            |if [ "§TASK5_FAKE_SCENARIO" = foreign-root-before-mkdir ] &&
            |  [ "§*" = "§root" ]; then
            |  /bin/mkdir "§root"
            |  chmod 700 "§root"
            |  printf '%s\n' foreign > "§root/sentinel"
            |  exit 73
            |fi
            |exec /bin/mkdir "§@"
            |
        """.trimMargin().replace('§', '$')

        private val FAKE_MKTEMP = """
            |#!/bin/sh
            |set -eu
            |if [ "§{TASK5_FAKE_GUARD_CHILD_ENV:-0}" = 1 ]; then
            |  task5-child-env-guard mktemp
            |fi
            |printf '%s\n' "mktemp §*" >> "§TASK5_FAKE_LOG"
            |if [ "§TASK5_FAKE_SCENARIO" = signal-after-baseline-mktemp ]; then
            |  [ "§#" -eq 2 ]
            |  [ "§1" = -d ]
            |  case "§2" in
            |    *"/mail-sandbox-task5-baseline.XXXXXX") ;;
            |    *) exit 64 ;;
            |  esac
            |  baseline="§{2%XXXXXX}signalbarrier"
            |  /bin/mkdir -m 700 "§baseline"
            |  : > "§TASK5_FAKE_STATE/baseline-mktemp-paused"
            |  while [ ! -f "§TASK5_FAKE_STATE/baseline-mktemp-resume" ]; do
            |    sleep 0.05
            |  done
            |  : > "§TASK5_FAKE_STATE/baseline-mktemp-finished"
            |  printf '%s\n' "§baseline"
            |  exit 0
            |fi
            |exec /usr/bin/mktemp "§@"
            |
        """.trimMargin().replace('§', '$')

        private val FAKE_LSOF = """
            |#!/bin/sh
            |set -eu
            |if [ "§{TASK5_FAKE_GUARD_CHILD_ENV:-0}" = 1 ]; then
            |  task5-child-env-guard lsof
            |fi
            |printf '%s\n' "lsof §*" >> "§TASK5_FAKE_LOG"
            |case "§TASK5_FAKE_SCENARIO" in
            |  port-collision)
            |    case "§*" in *"-iTCP:21995"*) exit 0 ;; esac
            |    ;;
            |  port-query-fails)
            |    case "§*" in *"-iTCP:1993"*) exit 2 ;; esac
            |    ;;
            |esac
            |exit 1
            |
        """.trimMargin().replace('§', '$')

        private val FAKE_INSTALL = """
            |#!/bin/sh
            |set -eu
            |if [ "§{TASK5_FAKE_GUARD_CHILD_ENV:-0}" = 1 ]; then
            |  task5-child-env-guard install
            |fi
            |printf '%s\n' "install §*" >> "§TASK5_FAKE_LOG"
            |if [ "§TASK5_FAKE_SCENARIO" = install-root-fails-after-create ] &&
            |  [ "§*" = "-d -m 700 §TASK5_FAKE_REPOSITORY/debug-dashboard/.runtime/task5-proof" ]; then
            |  mkdir -p "§TASK5_FAKE_REPOSITORY/debug-dashboard/.runtime/task5-proof"
            |  chmod 700 "§TASK5_FAKE_REPOSITORY/debug-dashboard/.runtime/task5-proof"
            |  exit 51
            |fi
            |[ "§1" = -d ]
            |[ "§2" = -m ]
            |[ "§3" = 700 ]
            |shift 3
            |for directory do
            |  mkdir -p "§directory"
            |  chmod 700 "§directory"
            |done
            |
        """.trimMargin().replace('§', '$')

        private val FAKE_OPENSSL = """
            |#!/bin/sh
            |set -eu
            |if [ "§{TASK5_FAKE_GUARD_CHILD_ENV:-0}" = 1 ]; then
            |  task5-child-env-guard openssl
            |fi
            |next_sequence() {
            |  sequence_lock="§TASK5_FAKE_STATE/openssl-sequence.lock"
            |  sequence_file="§TASK5_FAKE_STATE/openssl-sequence"
            |  while ! /bin/mkdir "§sequence_lock" 2>/dev/null; do
            |    sleep 0.01
            |  done
            |  sequence=0
            |  if [ -f "§sequence_file" ]; then
            |    IFS= read -r sequence < "§sequence_file"
            |  fi
            |  sequence=§((sequence + 1))
            |  printf '%s\n' "§sequence" > "§sequence_file"
            |  /bin/rmdir "§sequence_lock"
            |  printf '%s\n' "§sequence"
            |}
            |case "§{1:-}" in
            |  req)
            |    printf '%s\n' "openssl §*" >> "§TASK5_FAKE_LOG"
            |    expected="req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 -subj /CN=localhost -addext subjectAltName=DNS:localhost -keyout §TASK5_FAKE_REPOSITORY/debug-dashboard/.runtime/task5-proof/ssl/tls.key -out §TASK5_FAKE_REPOSITORY/debug-dashboard/.runtime/task5-proof/ssl/tls.crt"
            |    [ "§*" = "§expected" ]
            |    keyout=
            |    output=
            |    while [ "§#" -gt 0 ]; do
            |      case "§1" in
            |        -keyout) shift; keyout=§1 ;;
            |        -out) shift; output=§1 ;;
            |      esac
            |      shift
            |    done
            |    : > "§keyout"
            |    : > "§output"
            |    ;;
            |  verify)
            |    printf '%s\n' "openssl §*" >> "§TASK5_FAKE_LOG"
            |    expected="verify -CAfile §TASK5_FAKE_REPOSITORY/debug-dashboard/.runtime/task5-proof/ssl/tls.crt -verify_hostname localhost §TASK5_FAKE_REPOSITORY/debug-dashboard/.runtime/task5-proof/ssl/tls.crt"
            |    [ "§*" = "§expected" ]
            |    if [ "§TASK5_FAKE_SCENARIO" = certificate-verification-fails ]; then
            |      exit 94
            |    fi
            |    ;;
            |  rand)
            |    printf '%s\n' "openssl §*" >> "§TASK5_FAKE_LOG"
            |    if [ "§TASK5_FAKE_SCENARIO" = lock-token-generation-fails ] &&
            |      [ "§*" = "rand -hex 32" ]; then
            |      exit 93
            |    fi
            |    sequence="§(next_sequence)"
            |    if [ "§*" = "rand -hex 24" ]; then
            |      printf '%048x\n' "§sequence"
            |    elif [ "§*" = "rand -hex 32" ]; then
            |      printf '%064x\n' "§sequence"
            |    else
            |      exit 92
            |    fi
            |    ;;
            |  *)
            |    exit 91
            |    ;;
            |esac
            |
        """.trimMargin().replace('§', '$')

        private val FAKE_KOTLIN = """
            |#!/bin/sh
            |set -eu
            |if [ "§{TASK5_FAKE_GUARD_CHILD_ENV:-0}" = 1 ]; then
            |  task5-child-env-guard kotlin
            |fi
            |printf '%s\n' "docker-host §{DOCKER_HOST:-unset}" >> "§TASK5_FAKE_LOG"
            |[ "§{DOCKER_HOST:-unset}" = "unix:///var/run/docker.sock" ] ||
            |  exit 63
            |printf '%s\n' "kotlin §*" >> "§TASK5_FAKE_LOG"
            |proof_environment="§{DOVECOT_LIVE_TESTS:-unset} §{DOVECOT_LIVE_PROFILE:-unset} §{COMPOSE_PROJECT_NAME:-unset} §{COMPOSE_FILE:-unset} §{COMPOSE_DISABLE_ENV_FILE:-unset}"
            |printf '%s\n' "proof-env §proof_environment" >> "§TASK5_FAKE_LOG"
            |case "§*" in
            |  *"DovecotOperatorConfigTest"|*"DovecotOperatorCredentialStoreTest"|*"DovecotTask5ProofLifecycleTest")
            |    [ "§proof_environment" = "unset unset unset unset unset" ] ||
            |      exit 61
            |    ;;
            |  *)
            |    [ "§proof_environment" = "1 task5-proof mail-sandbox-task5-proof docker-compose.yml:debug-dashboard/dashboard-server/testResources/dovecot-gate0c/compose.task5-proof.yml 1" ] ||
            |      exit 62
            |    ;;
            |esac
            |case "§*" in
            |  "test --include-module dashboard-server --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorOwnedEvidenceLiveTest")
            |    root="§TASK5_FAKE_REPOSITORY/debug-dashboard/.runtime/task5-proof/provider-evidence"
            |    [ "§{TASK5_DOVECOT_EVIDENCE_ROOT:-unset}" = "§root" ]
            |    [ -d "§root" ]
            |    [ ! -L "§root" ]
            |    [ "§(stat -f '%Lp' "§root")" = 700 ]
            |    for evidence in \
            |      base-compose.json \
            |      proof-compose.json \
            |      ordinary-doveconf.txt \
            |      operator-doveconf.txt
            |    do
            |      [ -f "§root/§evidence" ]
            |      [ ! -L "§root/§evidence" ]
            |      [ "§(stat -f '%Lp' "§root/§evidence")" = 600 ]
            |      [ "§(stat -f '%z' "§root/§evidence")" -ge 1 ]
            |      [ "§(stat -f '%z' "§root/§evidence")" -le 1048576 ]
            |    done
            |    printf '%s\n' \
            |      'provider-evidence-contract 700 600 600 600 600' \
            |      >> "§TASK5_FAKE_LOG"
            |    ;;
            |  "test --include-module dashboard-server --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorExecTransportLiveTest")
            |    exec_proof_mode="§{TASK5_OPERATOR_EXEC_PROOF_MODE:-full}"
            |    case "§exec_proof_mode" in
            |      preflight|full|inventory-only) ;;
            |      *) exit 66 ;;
            |    esac
            |    printf '%s\n' \
            |      "task5-exec-proof-mode §exec_proof_mode" \
            |      >> "§TASK5_FAKE_LOG"
            |    if [ "§TASK5_FAKE_SCENARIO" = task7-preflight-fails ] &&
            |      [ "§exec_proof_mode" = preflight ]; then
            |      exit 31
            |    fi
            |    if [ "§TASK5_FAKE_SCENARIO" = task7-exec-full-fails ] &&
            |      [ "§exec_proof_mode" = full ]; then
            |      exit 32
            |    fi
            |    if [ "§TASK5_FAKE_SCENARIO" = task7-final-inventory-fails ] &&
            |      [ "§exec_proof_mode" = inventory-only ]; then
            |      exit 33
            |    fi
            |    ;;
            |  *"task5-proof preflight")
            |    root="§TASK5_FAKE_REPOSITORY/debug-dashboard/.runtime/task5-proof"
            |    IFS= read -r lock_token < "§TASK5_FAKE_GLOBAL_LOCK/owner"
            |    IFS= read -r root_token < "§root/.task5-proof-owner"
            |    [ "§lock_token" != "§root_token" ]
            |    printf '%s\n' ownership-tokens-distinct >> "§TASK5_FAKE_LOG"
            |    printf '%s\n' \
            |      "proof-modes §(stat -f '%Lp' "§root") §(stat -f '%Lp' "§root/dovecot") §(stat -f '%Lp' "§root/ssl") §(stat -f '%Lp' "§root/ssl/tls.crt") §(stat -f '%Lp' "§root/ssl/tls.key")" \
            |      >> "§TASK5_FAKE_LOG"
            |    ;;
            |  *"task5-proof add task5-bootstrap@local.test")
            |    IFS= read -r generated_secret
            |    [ "§{#generated_secret}" -eq 64 ]
            |    case "§generated_secret" in
            |      *[!0-9a-f]*) exit 64 ;;
            |    esac
            |    IFS= read -r lock_token < "§TASK5_FAKE_GLOBAL_LOCK/owner"
            |    [ "§generated_secret" != "§lock_token" ]
            |    ;;
            |  *"task5-proof remove task5-bootstrap@local.test")
            |    if [ "§TASK5_FAKE_SCENARIO" = bootstrap-remove-fails ]; then
            |      exit 41
            |    fi
            |    if [ "§TASK5_FAKE_SCENARIO" = lock-changed-during-bootstrap-cleanup ]; then
            |      lock="§TASK5_FAKE_GLOBAL_LOCK"
            |      printf '%s\n' foreign-token > "§lock/owner"
            |      chmod 600 "§lock/owner"
            |      printf '%s\n' foreign > "§lock/sentinel"
            |    fi
            |    ;;
            |  *"DovecotOperatorStartupLiveTest")
            |    runtime="§TASK5_FAKE_REPOSITORY/debug-dashboard/.runtime"
            |    root="§runtime/task5-proof"
            |    lock="§TASK5_FAKE_GLOBAL_LOCK"
            |    case "§TASK5_FAKE_SCENARIO" in
            |      runtime-swapped-before-cleanup)
            |        moved="§TASK5_FAKE_STATE/moved-runtime"
            |        external="§TASK5_FAKE_STATE/external-runtime"
            |        mv "§runtime" "§moved"
            |        /bin/mkdir -p "§external"
            |        printf '%s\n' keep > "§external/sentinel"
            |        ln -s "§external" "§runtime"
            |        exit 23
            |        ;;
            |      root-replaced-before-cleanup)
            |        mv "§root" "§TASK5_FAKE_STATE/original-proof-root"
            |        /bin/mkdir "§root"
            |        chmod 700 "§root"
            |        cp "§TASK5_FAKE_STATE/original-proof-root/.task5-proof-owner" \
            |          "§root/.task5-proof-owner"
            |        chmod 600 "§root/.task5-proof-owner"
            |        printf '%s\n' foreign > "§root/sentinel"
            |        exit 23
            |        ;;
            |      root-marker-inode-changed-before-cleanup)
            |        cp "§root/.task5-proof-owner" "§root/.owner-replacement"
            |        mv -f "§root/.owner-replacement" "§root/.task5-proof-owner"
            |        printf '%s\n' foreign > "§root/sentinel"
            |        exit 23
            |        ;;
            |      root-marker-token-changed-before-cleanup)
            |        printf '%s\n' foreign-token > "§root/.task5-proof-owner"
            |        chmod 600 "§root/.task5-proof-owner"
            |        printf '%s\n' foreign > "§root/sentinel"
            |        exit 23
            |        ;;
            |      lock-replaced-before-cleanup)
            |        mv "§lock" "§TASK5_FAKE_STATE/original-lifecycle-lock"
            |        /bin/mkdir "§lock"
            |        chmod 700 "§lock"
            |        cp "§TASK5_FAKE_STATE/original-lifecycle-lock/owner" \
            |          "§lock/owner"
            |        chmod 600 "§lock/owner"
            |        printf '%s\n' foreign > "§lock/sentinel"
            |        exit 23
            |        ;;
            |      lock-marker-inode-changed-before-cleanup)
            |        cp "§lock/owner" "§lock/owner-replacement"
            |        mv -f "§lock/owner-replacement" "§lock/owner"
            |        printf '%s\n' foreign > "§lock/sentinel"
            |        exit 23
            |        ;;
            |      lock-marker-token-changed-before-cleanup)
            |        printf '%s\n' foreign-token > "§lock/owner"
            |        chmod 600 "§lock/owner"
            |        printf '%s\n' foreign > "§lock/sentinel"
            |        exit 23
            |        ;;
            |      lock-mode-changed-before-cleanup)
            |        chmod 755 "§lock"
            |        printf '%s\n' foreign > "§lock/sentinel"
            |        exit 23
            |        ;;
            |      lock-extra-entry-before-cleanup)
            |        printf '%s\n' foreign > "§lock/sentinel"
            |        exit 23
            |        ;;
            |    esac
            |    if [ "§TASK5_FAKE_SCENARIO" = main-live-fails ] ||
            |      [ "§TASK5_FAKE_SCENARIO" = signal-during-cleanup-down ] ||
            |      [ "§TASK5_FAKE_SCENARIO" = lock-changed-during-bootstrap-cleanup ] ||
            |      [ "§TASK5_FAKE_SCENARIO" = main-and-down-fail ]; then
            |      exit 23
            |    fi
            |    ;;
            |esac
            |
        """.trimMargin().replace('§', '$')

        private val FAKE_PYTHON = """
            |#!/bin/sh
            |set -eu
            |if [ "§{TASK5_FAKE_GUARD_CHILD_ENV:-0}" = 1 ]; then
            |  task5-child-env-guard python3
            |fi
            |printf '%s\n' "python3 §*" >> "§TASK5_FAKE_LOG"
            |[ "§*" = "-m unittest debug-dashboard/dashboard-server/testResources/dovecot-gate0c/test_network_isolation_check.py" ]
            |[ "§{DOVECOT_LIVE_TESTS:-unset}" = unset ]
            |[ "§{DOVECOT_LIVE_PROFILE:-unset}" = unset ]
            |[ "§{COMPOSE_PROJECT_NAME:-unset}" = unset ]
            |[ "§{COMPOSE_FILE:-unset}" = unset ]
            |[ "§{COMPOSE_DISABLE_ENV_FILE:-unset}" = unset ]
            |[ "§{TASK5_OPERATOR_EXEC_PROOF_MODE:-unset}" = unset ]
            |
        """.trimMargin().replace('§', '$')

        private val FAKE_STAT = """
            |#!/bin/sh
            |set -eu
            |if [ "§{TASK5_FAKE_GUARD_CHILD_ENV:-0}" = 1 ]; then
            |  task5-child-env-guard stat
            |fi
            |printf '%s\n' "stat §*" >> "§TASK5_FAKE_LOG"
            |exec /usr/bin/stat "§@"
            |
        """.trimMargin().replace('§', '$')

        private val FAKE_CHILD_ENV_GUARD = """
            |#!/bin/sh
            |set -eu
            |tool="§1"
            |for variable in \
            |  TASK5_LIFECYCLE_LOCK_TOKEN \
            |  TASK5_PROOF_ROOT_TOKEN \
            |  token \
            |  actual_token
            |do
            |  case "§variable" in
            |    TASK5_LIFECYCLE_LOCK_TOKEN)
            |      value="§{TASK5_LIFECYCLE_LOCK_TOKEN-}"
            |      ;;
            |    TASK5_PROOF_ROOT_TOKEN)
            |      value="§{TASK5_PROOF_ROOT_TOKEN-}"
            |      ;;
            |    token)
            |      value="§{token-}"
            |      ;;
            |    actual_token)
            |      value="§{actual_token-}"
            |      ;;
            |  esac
            |  if [ -n "§value" ]; then
            |    printf '%s\n' \
            |      "child-env-leak §tool §variable §value" \
            |      >> "§TASK5_FAKE_LOG"
            |    exit 97
            |  fi
            |done
            |printf '%s\n' "child-env-clean §tool" >> "§TASK5_FAKE_LOG"
            |
        """.trimMargin().replace('§', '$')

        private val HOSTILE_BASH_ENV = """
            |task5_startup_debug_probe() {
            |  if [ -n "§{TASK5_LIFECYCLE_LOCK_TOKEN-}§{TASK5_PROOF_ROOT_TOKEN-}§{token-}§{actual_token-}" ]; then
            |    printf '%s\n' \
            |      "debug-token §{TASK5_LIFECYCLE_LOCK_TOKEN-} §{TASK5_PROOF_ROOT_TOKEN-} §{token-} §{actual_token-}" \
            |      >> "§TASK5_FAKE_STARTUP_INJECTION_LOG"
            |  fi
            |}
            |trap task5_startup_debug_probe DEBUG
            |set -T
            |printf '%s\n' bash-env-loaded >> "§TASK5_FAKE_STARTUP_INJECTION_LOG"
            |
        """.trimMargin().replace('§', '$')
    }

    private data class RuntimeSwapEvidence(
        val movedRuntime: Path,
        val externalRuntime: Path,
        val externalSentinel: Path,
    )
}

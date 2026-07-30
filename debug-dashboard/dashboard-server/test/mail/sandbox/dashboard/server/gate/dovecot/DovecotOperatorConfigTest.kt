package mail.sandbox.dashboard.server.gate.dovecot

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DovecotOperatorConfigTest {
    private val repositoryRoot = repositoryRoot()
    private val operatorConfigPath = repositoryRoot.resolve("config/operator/dovecot.conf")
    private val proofComposePath = repositoryRoot.resolve(
        "debug-dashboard/dashboard-server/testResources/" +
            "dovecot-gate0c/compose.task5-proof.yml",
    )
    private val proofLifecyclePath = repositoryRoot.resolve(
        "debug-dashboard/dashboard-server/testResources/" +
            "dovecot-gate0c/run-task5-proof.sh",
    )
    private val networkIsolationHelperPath = repositoryRoot.resolve(
        "debug-dashboard/dashboard-server/testResources/" +
            "dovecot-gate0c/network-isolation-check.py",
    )
    private val implementationPlanPath = repositoryRoot.resolve(
        "docs/superpowers/plans/2026-07-23-debug-dashboard-gate-0c-dovecot.md",
    )
    private val designSpecPath = repositoryRoot.resolve(
        "docs/superpowers/specs/2026-07-23-debug-dashboard-design.md",
    )
    private val startupLiveTestPath = repositoryRoot.resolve(
        "debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/" +
            "server/gate/dovecot/DovecotOperatorStartupLiveTest.kt",
    )
    private val serviceMapPath = repositoryRoot.resolve(
        ".ai/skills/docker-compose/references/service-map.md",
    )
    private val volumeMountsPath = repositoryRoot.resolve(
        ".ai/skills/docker-compose/references/volume-mounts.md",
    )
    private val configFilesReferencePath = repositoryRoot.resolve(
        ".ai/skills/dovecot/references/config-files.md",
    )
    private val authReferencePath = repositoryRoot.resolve(
        ".ai/skills/dovecot/references/auth.md",
    )

    @Test
    fun standaloneOperatorConfigIsTheExactReviewedImapsOnlyMasterBoundary() {
        assertEquals(EXPECTED_OPERATOR_CONFIG, Files.readString(operatorConfigPath))
    }

    @Test
    fun pinnedEffectiveConfigKeepsPreinitSafeMasterDirectEligibilityMissingOrder() {
        val effective = effectiveOperatorConfig()
        val passdbs = topLevelNamedBlocks(effective, "passdb")
        val assignments = topLevelAssignments(effective)

        assertLoginOnlyCombinedMasterForm(effective)
        assertEquals(
            listOf(
                "operator-master",
                "deny-direct",
                "eligible-target",
                "deny-missing",
            ),
            passdbs.keys.toList(),
        )
        assertEquals(
            mapOf(
                "driver" to "passwd-file",
                "master" to "yes",
                "result_success" to "continue",
                "passwd_file_path" to "/etc/dovecot/operator-auth/master-users",
            ),
            passdbs.getValue("operator-master"),
        )
        assertEquals(
            mapOf(
                "deny" to "yes",
                "driver" to "static",
                "skip" to "authenticated",
            ),
            passdbs.getValue("deny-direct"),
        )
        assertEquals(
            mapOf(
                "driver" to "passwd-file",
                "passwd_file_path" to "/etc/dovecot/runtime/users",
                "result_failure" to "continue-fail",
                "result_internalfail" to "return-fail",
                "skip" to "unauthenticated",
            ),
            passdbs.getValue("eligible-target"),
        )
        assertEquals(
            mapOf(
                "deny" to "yes",
                "driver" to "static",
            ),
            passdbs.getValue("deny-missing"),
        )
        listOf("deny-direct", "deny-missing").forEach { denyPassdb ->
            assertEquals(
                mapOf(
                    "nopassword" to "yes",
                    "nodelay" to "yes",
                ),
                nestedBlockAssignments(
                    text = effective,
                    outerBlockType = "passdb",
                    outerBlockName = denyPassdb,
                    nestedBlockName = "fields",
                ),
            )
        }
        assertFalse("noauthenticate" in effective)
        assertEquals("2.4.0", assignments.getValue("dovecot_storage_version"))
        assertEquals("maildir", assignments.getValue("mail_driver"))
        assertEquals("~/Maildir", assignments.getValue("mail_path"))
        assertEquals("index", assignments.getValue("mailbox_list_layout"))
        assertEquals("yes", assignments["mailbox_list_utf8"], assignments.toString())
        assertEquals("yes", assignments.getValue("mail_utf8_extensions"))
        assertEquals("vmail", assignments.getValue("mail_uid"))
        assertEquals("vmail", assignments.getValue("mail_gid"))
    }

    @Test
    fun firstNonMasterPassdbCannotBeUnauthenticatedSkip() {
        val passdbs = topLevelNamedBlocks(effectiveOperatorConfig(), "passdb")
        val firstNonMaster = passdbs.entries.first { it.value["master"] != "yes" }

        assertEquals(
            "deny-direct",
            firstNonMaster.key,
            "Dovecot 2.4.1 auth_preinit silently omits a leading non-master " +
                "passdb with skip=unauthenticated",
        )
        assertEquals(
            "authenticated",
            firstNonMaster.value["skip"],
            "The preinit anchor must deny direct logins but be skipped after " +
                "the master password is verified",
        )
    }

    @Test
    fun operatorEndpointRejectsThePlainAuthzidMasterFormByMechanism() {
        val configured = Files.readString(operatorConfigPath)
        val mutated = configured.replace(
            "auth_mechanisms = login\n",
            "auth_mechanisms = plain login\n",
        )
        assertTrue(mutated != configured, "LOGIN-only operator setting was not found")

        assertLoginOnlyCombinedMasterForm(effectiveOperatorConfig())
        val mutatedConfig = Files.createTempFile(
            "dovecot-operator-plain-authzid-",
            ".conf",
        )
        try {
            Files.writeString(mutatedConfig, mutated)
            assertFailsWith<AssertionError> {
                assertLoginOnlyCombinedMasterForm(
                    effectiveOperatorConfig(mutatedConfig),
                )
            }
        } finally {
            Files.deleteIfExists(mutatedConfig)
        }
    }

    @Test
    fun pinnedOrdinaryEffectiveConfigRejectsEveryMasterPassdbMutation() {
        assertOrdinaryHasNoMasterPassdb(effectiveOrdinaryConfig())

        val mutatedConfig = Files.createTempDirectory(
            "dovecot-ordinary-master-regression-",
        )
        try {
            Files.list(repositoryRoot.resolve("config")).use { entries ->
                entries
                    .filter { path ->
                        Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                    }
                    .forEach { source ->
                        Files.copy(
                            source,
                            mutatedConfig.resolve(source.fileName),
                        )
                    }
            }
            Files.writeString(
                mutatedConfig.resolve("99-task5-master-regression.conf"),
                """
                passdb task5_regression_master {
                  driver = passwd-file
                  passwd_file_path = /etc/dovecot/operator-auth/master-users
                  fields {
                    user = %{user}
                  }
                  master = yes
                  result_success = continue
                }
                """.trimIndent() + "\n",
            )
            val mutatedEffective = effectiveOrdinaryConfig(mutatedConfig)
            assertEquals(
                setOf("task5_regression_master"),
                masterPassdbNames(mutatedEffective),
            )
            assertFailsWith<AssertionError> {
                assertOrdinaryHasNoMasterPassdb(mutatedEffective)
            }
        } finally {
            Files.list(mutatedConfig).use { entries ->
                entries.forEach(Files::deleteIfExists)
            }
            Files.deleteIfExists(mutatedConfig)
        }
    }

    @Test
    fun defaultComposeOmitsOperatorUntilItsExplicitProfileIsSelected() {
        val defaultServices = resolvedCompose().requiredObject("services")
        assertEquals(
            setOf("dovecot", "postfix", "oauth2-mock", "stalwart"),
            defaultServices.keys,
        )
        assertFalse("dovecot-operator" in defaultServices)

        val activatedServices = resolvedOperatorCompose().requiredObject("services")
        assertEquals(defaultServices.keys + "dovecot-operator", activatedServices.keys)
        assertEquals(
            listOf(OPERATOR_PROFILE),
            activatedServices.requiredObject("dovecot-operator")
                .requiredArray("profiles")
                .map { it.jsonPrimitive.content },
        )
    }

    @Test
    fun resolvedComposeKeepsOperatorIngressLoopbackOnlyAndIsolated() {
        val resolved = resolvedOperatorCompose()
        val services = resolved.requiredObject("services")
        val ordinary = services.requiredObject("dovecot")
        val operator = services.requiredObject("dovecot-operator")

        assertEquals(PINNED_DOVECOT_IMAGE, operator.requiredString("image"))
        assertEquals("unless-stopped", operator.requiredString("restart"))
        assertEquals(
            setOf("operator-ingress"),
            operator.requiredObject("networks").keys,
        )
        assertEquals(
            setOf("default"),
            ordinary.requiredObject("networks").keys,
        )
        services.forEach { (name, value) ->
            if (name != "dovecot-operator") {
                assertFalse(
                    "operator-ingress" in value.jsonObject.requiredObject("networks"),
                    "$name must not join the operator ingress network",
                )
            }
        }
        assertFalse(
            resolved.requiredObject("networks")
                .requiredObject("operator-ingress")["internal"]
                ?.jsonPrimitive
                ?.boolean ?: false,
            "An internal bridge suppresses Docker's loopback host publication",
        )

        assertEquals(
            listOf(
                PortPublication(
                    hostIp = "127.0.0.1",
                    published = "2993",
                    target = 31993,
                    protocol = "tcp",
                    mode = "ingress",
                ),
            ),
            operator.requiredArray("ports").map(::portPublication),
        )
    }

    @Test
    fun operatorIngressDocumentationRequiresAQuietOperationalHealthcheck() {
        val plan = Files.readString(implementationPlanPath)
        val task5 = plan
            .substringAfter("## Task 5:")
            .substringBefore("## Task 6:")
        val gate0cSpec = Files.readString(designSpecPath)
            .substringAfter("### Gate 0C — Dovecot operator access")
            .substringBefore("### Gate 1 — Live parity suite")

        assertFalse("joins its own internal Docker network" in plan)
        assertTrue(
            "dedicated non-internal Docker bridge whose sole service member " +
                "is the operator" in plan,
        )
        assertFalse("`operator-ingress` internal network" in task5)
        assertTrue(
            "dedicated `operator-ingress` non-internal bridge with no other " +
                "service" in task5,
        )
        assertTrue(
            "dedicated non-internal project bridge whose only service member " +
                "is the operator" in gate0cSpec,
        )
        val serviceStatusContract =
            "requires a positive integer `process_count`, exact " +
                "`throttle_secs: 0`, and exact `doveadm_stop: n` for both " +
                "`auth` and `imap-login`"
        val listenerContract =
            "passively matches IPv4 LISTEN state `0A` for container port " +
                "`31993` (`7CF9`) in `/proc/net/tcp` without connecting"
        listOf(task5, gate0cSpec).forEach { document ->
            assertFalse("requires exact `listening: y` status" in document)
            assertTrue(serviceStatusContract in document)
            assertTrue(listenerContract in document)
            assertTrue(
                "host JSSE readiness remains the end-to-end gate" in document,
            )
        }
    }

    @Test
    fun operatorAuthDocumentationRequiresPreinitSafeFourPassdbChain() {
        val plan = Files.readString(implementationPlanPath)
            .substringAfter("## Task 5:")
            .substringBefore("## Task 6:")
        val gate0cSpec = Files.readString(designSpecPath)
            .substringAfter("### Gate 0C — Dovecot operator access")
            .substringBefore("### Gate 1 — Live parity suite")
        val preinitContract =
            "Dovecot 2.4.1 `auth_preinit` silently omits a first non-master " +
                "passdb with `skip = unauthenticated`"
        val chainContract =
            "`operator-master` → `deny-direct` → `eligible-target` → " +
                "`deny-missing`"
        val fallbackContract =
            "Both deny passdbs set `deny = yes`, `nopassword = yes`, and " +
                "`nodelay = yes`."
        val behaviorContract =
            "The canonical `result_success = continue` marks the master " +
                "password verified, jumps to the first non-master passdb, " +
                "and does not pre-authorize the target."
        val resultContract =
            "`eligible-target` uses `skip = unauthenticated`, " +
                "`result_failure = continue-fail`, and " +
                "`result_internalfail = return-fail`."

        listOf(plan, gate0cSpec).forEach { document ->
            assertFalse("noauthenticate = yes" in document)
            assertFalse("result_success = continue-ok" in document)
            assertTrue(preinitContract in document)
            assertTrue(chainContract in document)
            assertTrue(fallbackContract in document)
            assertTrue(behaviorContract in document)
            assertTrue(resultContract in document)
        }
    }

    @Test
    fun task5LiveProofDeniesBareTargetLoginBeforeMasterLoginAndWipesBuffers() {
        val source = Files.readString(startupLiveTestPath)
        val addEligible = source.indexOf("addEligibleTarget(")
        val directLogin = source.indexOf(
            "assertEligibleTargetPasswordRejected(",
        )
        val plainAuthzid = source.indexOf(
            "assertPlainAuthzidMasterFormRejected(",
        )
        val masterLogin = source.indexOf(
            "val result = probe.probe(target, credential)",
        )

        assertTrue(addEligible >= 0)
        assertTrue(directLogin > addEligible)
        assertTrue(plainAuthzid > directLogin)
        assertTrue(masterLogin > plainAuthzid)
        assertTrue("A901 AUTHENTICATE LOGIN\\r\\n" in source)
        assertTrue("completion.startsWithAscii(\"A901 NO\")" in source)
        assertTrue("EligibilityPassword" in source)
        assertTrue("targetPassword.withBytes" in source)
        assertTrue("credentialBuffers.all" in source)
        assertFalse("decodeToString" in source)
    }

    @Test
    fun repositorySkillReferencesTrackCurrentDovecotTopologyAndAuthorities() {
        val serviceMap = Files.readString(serviceMapPath)
        val volumeMounts = Files.readString(volumeMountsPath)
        val configFiles = Files.readString(configFilesReferencePath)
        val auth = Files.readString(authReferencePath)

        listOf(
            "`127.0.0.1:1143` → `31143`",
            "`127.0.0.1:1993` → `31993`",
            "`127.0.0.1:1110` → `31110`",
            "`127.0.0.1:1995` → `31990`",
            "`127.0.0.1:2993` → `31993`",
            "`127.0.0.1:1025` → `25`",
            "`127.0.0.1:1465` → `465`",
            "`127.0.0.1:1587` → `587`",
            "`127.0.0.1:8080` → `8080`",
            "`0.0.0.0:8443` → `8443`",
        ).forEach { mapping ->
            assertTrue(mapping in serviceMap, "missing service mapping: $mapping")
        }
        assertTrue("explicit `dovecot-operator` profile" in serviceMap)
        assertTrue("only service attached to `operator-ingress`" in serviceMap)
        assertFalse("dovecot-dev" in serviceMap)
        assertFalse("stalwart-dev" in serviceMap)

        listOf(
            "`./debug-dashboard/.runtime/dovecot`",
            "`/etc/dovecot/runtime`",
            "`./config/operator/dovecot.conf`",
            "`/etc/dovecot/dovecot.conf`",
            "`./debug-dashboard/.runtime/dovecot-operator`",
            "`/etc/dovecot/operator-auth`",
            "`create_host_path: false`",
        ).forEach { mountContract ->
            assertTrue(mountContract in volumeMounts)
        }
        assertTrue("hash-only `master-users`" in volumeMounts)

        listOf(
            "`20-doveadm.conf`",
            "`20-pop3.conf`",
            "`users.seed`",
            "`operator/dovecot.conf`",
            "`debug-dashboard/.runtime/dovecot/users`",
        ).forEach { inventoryContract ->
            assertTrue(inventoryContract in configFiles)
        }
        assertFalse("`users`             | Passwd-file" in configFiles)
        assertFalse("{PLAIN}" in configFiles)

        assertTrue(
            "`debug-dashboard/.runtime/dovecot/users`" in auth,
        )
        assertTrue("{ARGON2ID}" in auth)
        assertTrue(
            "`operator-master` → `deny-direct` → `eligible-target` → " +
                "`deny-missing`" in auth,
        )
        assertTrue("`result_success = continue`" in auth)
        assertTrue(
            "`auth_preinit` silently omits a first non-master passdb" in auth,
        )
        assertTrue("`skip = unauthenticated`" in auth)
        assertTrue("`result_failure = continue-fail`" in auth)
        assertTrue("`result_internalfail = return-fail`" in auth)
        assertFalse("result_success = continue-ok" in auth)
        assertFalse("`config/users`" in auth)
        assertFalse("{PLAIN}" in auth)
    }

    @Test
    fun resolvedComposeUsesOnlyReviewedOperatorMountsAndNeverMountsRawSecrets() {
        val services = resolvedOperatorCompose().requiredObject("services")
        val ordinaryMounts = services.requiredObject("dovecot")
            .requiredArray("volumes")
            .map(::mount)
        val operatorMounts = services.requiredObject("dovecot-operator")
            .requiredArray("volumes")
            .map(::mount)
        val operatorAuthVolume = services.requiredObject("dovecot-operator")
            .requiredArray("volumes")
            .map { it.jsonObject }
            .single {
                it.requiredString("target") == "/etc/dovecot/operator-auth"
            }

        assertEquals(
            listOf(
                Mount(
                    source = repositoryRoot.resolve("config/operator/dovecot.conf"),
                    target = "/etc/dovecot/dovecot.conf",
                    readOnly = true,
                ),
                Mount(
                    source = repositoryRoot.resolve("debug-dashboard/.runtime/dovecot"),
                    target = "/etc/dovecot/runtime",
                    readOnly = true,
                ),
                Mount(
                    source = repositoryRoot.resolve(
                        "debug-dashboard/.runtime/dovecot-operator",
                    ),
                    target = "/etc/dovecot/operator-auth",
                    readOnly = true,
                ),
                Mount(
                    source = repositoryRoot.resolve("ssl"),
                    target = "/etc/dovecot/ssl",
                    readOnly = true,
                ),
                Mount(
                    source = repositoryRoot.resolve("vmail"),
                    target = "/srv/vmail",
                    readOnly = false,
                ),
            ),
            operatorMounts,
        )
        assertEquals(
            emptySet(),
            operatorAuthVolume.requiredObject("bind").keys,
            "The security-owned operator bind must disable host-path creation",
        )
        assertTrue(
            ordinaryMounts.none { mount ->
                mount.target == "/etc/dovecot/operator-auth" ||
                    mount.source.endsWith("dovecot-operator")
            },
        )
        (ordinaryMounts + operatorMounts).forEach { mount ->
            assertFalse(
                mount.source.startsWith(
                    repositoryRoot.resolve("debug-dashboard/.runtime/secrets"),
                ),
            )
            assertFalse(mount.source.fileName.toString().startsWith("dovecot-operator-"))
        }
    }

    @Test
    fun resolvedComposePinsBoundedQuietOperationalHealthcheck() {
        val health = resolvedOperatorCompose()
            .requiredObject("services")
            .requiredObject("dovecot-operator")
            .requiredObject("healthcheck")

        assertEquals(
            listOf(
                "CMD",
                "sh",
                "-c",
                "auth_status=\"\$\$(doveadm service status auth)\" && " +
                    "printf '%s\\n' \"\$\$auth_status\" | " +
                    "grep -Eqx 'process_count: [1-9][0-9]*' && " +
                    "printf '%s\\n' \"\$\$auth_status\" | " +
                    "grep -qx 'throttle_secs: 0' && " +
                    "printf '%s\\n' \"\$\$auth_status\" | " +
                    "grep -qx 'doveadm_stop: n' && " +
                    "imap_login_status=\"\$\$(" +
                    "doveadm service status imap-login)\" && " +
                    "printf '%s\\n' \"\$\$imap_login_status\" | " +
                    "grep -Eqx 'process_count: [1-9][0-9]*' && " +
                    "printf '%s\\n' \"\$\$imap_login_status\" | " +
                    "grep -qx 'throttle_secs: 0' && " +
                    "printf '%s\\n' \"\$\$imap_login_status\" | " +
                    "grep -qx 'doveadm_stop: n' && " +
                    "grep -Eq '^[[:space:]]*[0-9]+:[[:space:]]+" +
                    "[[:xdigit:]]{8}:7CF9[[:space:]]+" +
                    "[[:xdigit:]]{8}:[[:xdigit:]]{4}[[:space:]]+" +
                    "0A[[:space:]]' /proc/net/tcp",
            ),
            health.requiredArray("test").map { it.jsonPrimitive.content },
        )
        assertEquals("5s", health.requiredString("interval"))
        assertEquals("3s", health.requiredString("timeout"))
        assertEquals("10s", health.requiredString("start_period"))
        assertEquals(5, health.requiredInt("retries"))
    }

    @Test
    fun proofOverrideExplicitlyClearsTheProductionOperatorProfile() {
        val configured = Files.readString(proofComposePath)
        val clearProfile = "    profiles: !override []\n"
        assertTrue(
            clearProfile in configured,
            "The fixed proof must explicitly clear the production operator profile",
        )
        assertFalse(
            "profiles" in resolvedProofCompose()
                .requiredObject("services")
                .requiredObject("dovecot-operator"),
        )

        val mutated = configured.replace(clearProfile, "")
        assertTrue(mutated != configured, "Operator profile clear was not found")
        val mutatedOverride = Files.createTempFile(
            "task5-proof-without-operator-profile-clear-",
            ".yml",
        )
        try {
            Files.writeString(mutatedOverride, mutated)
            assertFalse(
                "dovecot-operator" in resolvedProofCompose(mutatedOverride)
                    .requiredObject("services"),
                "Mutation unexpectedly retained the unselected operator service",
            )
        } finally {
            Files.deleteIfExists(mutatedOverride)
        }
    }

    @Test
    fun resolvedProofComposeUsesOnlyTheFixedIsolatedTopology() {
        val resolved = resolvedProofCompose()
        val services = resolved.requiredObject("services")
        assertEquals(
            setOf("dovecot", "dovecot-operator", "postfix", "oauth2-mock"),
            services.keys,
        )
        assertEquals(
            mapOf(
                "dovecot" to listOf(
                    PortPublication(
                        hostIp = "127.0.0.1",
                        published = "1993",
                        target = 31993,
                        protocol = "tcp",
                        mode = "ingress",
                    ),
                    PortPublication(
                        hostIp = "127.0.0.1",
                        published = "21995",
                        target = 31990,
                        protocol = "tcp",
                        mode = "ingress",
                    ),
                ),
                "dovecot-operator" to listOf(
                    PortPublication(
                        hostIp = "127.0.0.1",
                        published = "2993",
                        target = 31993,
                        protocol = "tcp",
                        mode = "ingress",
                    ),
                ),
                "postfix" to listOf(
                    PortPublication(
                        hostIp = "127.0.0.1",
                        published = "21025",
                        target = 25,
                        protocol = "tcp",
                        mode = "ingress",
                    ),
                ),
                "oauth2-mock" to listOf(
                    PortPublication(
                        hostIp = "127.0.0.1",
                        published = "28080",
                        target = 8080,
                        protocol = "tcp",
                        mode = "ingress",
                    ),
                ),
            ),
            services.mapValues { (_, value) ->
                value.jsonObject.requiredArray("ports")
                    .map(::portPublication)
            },
        )
        assertEquals(
            setOf("default", "operator-ingress"),
            resolved.requiredObject("networks").keys,
        )

        val proofRoot = repositoryRoot.resolve(
            "debug-dashboard/.runtime/task5-proof",
        )
        fun source(
            service: String,
            target: String,
        ): String = services.requiredObject(service)
            .requiredArray("volumes")
            .map { it.jsonObject }
            .single { it.requiredString("target") == target }
            .requiredString("source")
        assertEquals(
            proofRoot.resolve("dovecot").toString(),
            source("dovecot", "/etc/dovecot/runtime"),
        )
        assertEquals(
            proofRoot.resolve("dovecot").toString(),
            source("dovecot-operator", "/etc/dovecot/runtime"),
        )
        assertEquals(
            proofRoot.resolve("dovecot-operator").toString(),
            source("dovecot-operator", "/etc/dovecot/operator-auth"),
        )
        assertEquals(
            proofRoot.resolve("dovecot").toString(),
            source("oauth2-mock", "/etc/dovecot/runtime"),
        )
        assertEquals(
            networkIsolationHelperPath.toString(),
            source("oauth2-mock", "/proof/network-isolation-check.py"),
        )
        val helperMount = services.requiredObject("oauth2-mock")
            .requiredArray("volumes")
            .map { it.jsonObject }
            .single {
                it.requiredString("target") == "/proof/network-isolation-check.py"
            }
        assertTrue(helperMount["read_only"]?.jsonPrimitive?.boolean == true)
        assertEquals(emptySet(), helperMount.requiredObject("bind").keys)
        assertEquals(
            listOf("task6-host-gateway=host-gateway"),
            services.requiredObject("oauth2-mock")
                .requiredArray("extra_hosts")
                .map { it.jsonPrimitive.content },
        )
        assertTrue(Files.isRegularFile(networkIsolationHelperPath))
        assertFalse(Files.isSymbolicLink(networkIsolationHelperPath))
        listOf(
            "dovecot" to "/etc/dovecot/ssl",
            "dovecot-operator" to "/etc/dovecot/ssl",
            "postfix" to "/etc/postfix/ssl",
        ).forEach { (service, target) ->
            assertEquals(
                proofRoot.resolve("ssl").toString(),
                source(service, target),
            )
        }
        services.values
            .flatMap { service ->
                service.jsonObject.requiredArray("volumes")
                    .map { it.jsonObject }
            }
            .filter { volume ->
                volume.requiredString("type") == "bind" &&
                    Path.of(volume.requiredString("source"))
                        .startsWith(proofRoot)
            }
            .forEach { proofBind ->
                assertEquals(
                    emptySet(),
                    proofBind.requiredObject("bind").keys,
                    "Proof-owned bind must disable host-path creation",
                )
            }

        val ordinaryVolumes = services.requiredObject("dovecot")
            .requiredArray("volumes")
            .map { it.jsonObject }
        val operatorVolumes = services.requiredObject("dovecot-operator")
            .requiredArray("volumes")
            .map { it.jsonObject }
        assertEquals(
            "task5-proof-vmail",
            ordinaryVolumes.single {
                it.requiredString("target") == "/srv/vmail"
            }.requiredString("source"),
        )
        assertEquals(
            "task5-proof-logs",
            ordinaryVolumes.single {
                it.requiredString("target") == "/var/log/dovecot"
            }.requiredString("source"),
        )
        assertEquals(
            "task5-proof-vmail",
            operatorVolumes.single {
                it.requiredString("target") == "/srv/vmail"
            }.requiredString("source"),
        )
        assertTrue(
            (ordinaryVolumes + operatorVolumes)
                .filter {
                    it.requiredString("target") == "/srv/vmail" ||
                        it.requiredString("target") == "/var/log/dovecot"
                }
                .all { it.requiredString("type") == "volume" },
        )
        assertEquals(
            mapOf(
                "task5-proof-vmail" to
                    "mail-sandbox-task5-proof_task5-proof-vmail",
                "task5-proof-logs" to
                    "mail-sandbox-task5-proof_task5-proof-logs",
            ),
            resolved.requiredObject("volumes").mapValues { (_, value) ->
                value.jsonObject.requiredString("name")
            },
        )
    }

    @Test
    fun task5RunbookDelegatesToTheCheckedFailClosedLifecycle() {
        val runbook = Files.readString(implementationPlanPath)
        val task5 = runbook
            .substringAfter("## Task 5:")
            .substringBefore("## Task 6:")
        val source = Files.readString(proofLifecyclePath)

        assertTrue(
            "./debug-dashboard/dashboard-server/testResources/" +
                "dovecot-gate0c/run-task5-proof.sh" in task5,
        )
        assertTrue("fail-closed lifecycle" in task5)
        assertFalse("Phase 1 —" in task5)
        assertFalse("Phase 4 —" in task5)
        assertTrue(source.startsWith("#!/bin/bash -p\n"))
        assertTrue("set -euo pipefail" in source)
        assertTrue("trap 'task5_on_exit \$?' EXIT" in source)
        assertTrue(
            "{{with (index .State \"Health\")}}{{.Status}}" +
                "{{else}}none{{end}}" in source,
        )
    }

    @Test
    fun currentAuthoritiesContainNoProtectedOrUnknownMasterIdentity() {
        val protected = setOf(
            "dashboard-management@local.test",
            "dashboard-operator-a@local.test",
            "dashboard-operator-b@local.test",
        )
        val ordinaryAuthority = repositoryRoot.resolve(
            "debug-dashboard/.runtime/dovecot/users",
        )
        Files.readAllLines(
            repositoryRoot.resolve("config/users.seed"),
            StandardCharsets.UTF_8,
        ).forEach { address ->
            assertEquals(address, EligibilityAddress.requireCanonical(address))
            assertTrue(address !in protected)
        }
        if (Files.exists(ordinaryAuthority, LinkOption.NOFOLLOW_LINKS)) {
            assertTrue(Files.isRegularFile(ordinaryAuthority, LinkOption.NOFOLLOW_LINKS))
            assertFalse(Files.isSymbolicLink(ordinaryAuthority))
            val document = EligibilityDocument.parse(Files.readString(ordinaryAuthority))
            assertTrue(document.addresses().none(protected::contains))
        }

        val masterAuthority = repositoryRoot.resolve(
            "debug-dashboard/.runtime/dovecot-operator/master-users",
        )
        if (Files.exists(masterAuthority, LinkOption.NOFOLLOW_LINKS)) {
            assertTrue(Files.isRegularFile(masterAuthority, LinkOption.NOFOLLOW_LINKS))
            assertFalse(Files.isSymbolicLink(masterAuthority))
            val lines = Files.readAllLines(masterAuthority, StandardCharsets.US_ASCII)
            assertEquals(1, lines.size)
            val delimiter = lines.single().indexOf(':')
            assertTrue(delimiter > 0)
            assertTrue(
                lines.single().substring(0, delimiter) in
                    setOf("dashboard-operator-a", "dashboard-operator-b"),
            )
            EligibilityEntry.requireValidHash(lines.single().substring(delimiter + 1))
        }
    }

    private fun resolvedCompose(): JsonObject {
        val output = runBoundedProcess(
            command = listOf("docker", "compose", "config", "--format", "json"),
            timeout = COMPOSE_TIMEOUT,
            description = "docker compose config",
        )
        return Json.parseToJsonElement(output).jsonObject
    }

    private fun resolvedOperatorCompose(): JsonObject {
        val output = runBoundedProcess(
            command = listOf(
                "docker",
                "compose",
                "--profile",
                OPERATOR_PROFILE,
                "config",
                "--format",
                "json",
            ),
            timeout = COMPOSE_TIMEOUT,
            description = "profile-qualified operator docker compose config",
        )
        return Json.parseToJsonElement(output).jsonObject
    }

    private fun resolvedProofCompose(
        overridePath: Path = proofComposePath,
    ): JsonObject {
        val output = runBoundedProcess(
            command = listOf(
                "docker",
                "compose",
                "--project-name",
                "mail-sandbox-task5-proof",
                "-f",
                "docker-compose.yml",
                "-f",
                overridePath.toString(),
                "config",
                "--format",
                "json",
            ),
            timeout = COMPOSE_TIMEOUT,
            description = "fixed proof docker compose config",
        )
        return Json.parseToJsonElement(output).jsonObject
    }

    private fun effectiveOperatorConfig(
        configPath: Path = operatorConfigPath,
    ): String = runBoundedProcess(
        command = listOf(
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "/dovecot/bin/doveconf",
            "-v",
            "$configPath:/etc/dovecot/dovecot.conf:ro",
            PINNED_DOVECOT_IMAGE,
            "-n",
        ),
        timeout = COMPOSE_TIMEOUT,
        description = "pinned operator doveconf",
    )

    private fun effectiveOrdinaryConfig(
        configDirectory: Path = repositoryRoot.resolve("config"),
    ): String = runBoundedProcess(
        command = listOf(
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "/dovecot/bin/doveconf",
            "-v",
            "$configDirectory:/etc/dovecot/conf.d:ro",
            PINNED_DOVECOT_IMAGE,
            "-n",
        ),
        timeout = COMPOSE_TIMEOUT,
        description = "pinned ordinary doveconf",
    )

    private fun assertLoginOnlyCombinedMasterForm(effective: String) {
        assertEquals(
            "login",
            topLevelAssignments(effective)["auth_mechanisms"],
            "SASL PLAIN permits the forbidden authorization-ID master form",
        )
    }

    private fun assertOrdinaryHasNoMasterPassdb(effective: String) {
        assertEquals(
            emptySet(),
            masterPassdbNames(effective),
            "The ordinary Dovecot effective config must never load a master passdb",
        )
    }

    private fun masterPassdbNames(effective: String): Set<String> =
        topLevelNamedBlocks(effective, "passdb")
            .filterValues { assignments ->
                assignments["master"] == "yes"
            }
            .keys

    private fun runBoundedProcess(
        command: List<String>,
        timeout: Duration,
        description: String,
    ): String {
        val process = ProcessBuilder(command)
            .directory(repositoryRoot.toFile())
            .redirectErrorStream(false)
            .start()
        val readers = Executors.newFixedThreadPool(2) { runnable ->
            Thread(runnable, "operator-config-command-output").also {
                it.isDaemon = true
            }
        }
        val stdoutFuture = readers.submit<ByteArray> {
            process.inputStream.readNBytes(MAX_COMPOSE_OUTPUT_BYTES + 1)
        }
        val stderrFuture = readers.submit<ByteArray> {
            process.errorStream.readNBytes(MAX_COMPOSE_OUTPUT_BYTES + 1)
        }
        var stdout = ByteArray(0)
        var stderr = ByteArray(0)
        try {
            assertTrue(
                process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS),
                "$description timed out",
            )
            stdout = stdoutFuture.get(OUTPUT_JOIN_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)
            stderr = stderrFuture.get(OUTPUT_JOIN_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)
            assertEquals(0, process.exitValue(), "$description failed")
            assertTrue(stdout.size <= MAX_COMPOSE_OUTPUT_BYTES)
            assertTrue(stderr.size <= MAX_COMPOSE_OUTPUT_BYTES)
            return stdout.toString(StandardCharsets.UTF_8)
        } finally {
            runCatching { process.inputStream.close() }
            runCatching { process.errorStream.close() }
            runCatching { process.outputStream.close() }
            process.destroyForcibly()
            stdoutFuture.cancel(true)
            stderrFuture.cancel(true)
            readers.shutdownNow()
            runCatching {
                readers.awaitTermination(
                    OUTPUT_JOIN_TIMEOUT.toMillis(),
                    TimeUnit.MILLISECONDS,
                )
            }
            stdout.fill(0)
            stderr.fill(0)
        }
    }

    private fun topLevelNamedBlocks(
        text: String,
        blockType: String,
    ): Map<String, Map<String, String>> {
        val lines = text.lines()
        val result = linkedMapOf<String, Map<String, String>>()
        val blockStart = Regex("""^${Regex.escape(blockType)} (.+) \{$""")
        var index = 0
        while (index < lines.size) {
            val match = blockStart.matchEntire(lines[index])
            if (match == null) {
                index += 1
                continue
            }
            val name = match.groupValues[1]
            val assignments = linkedMapOf<String, String>()
            var depth = 1
            index += 1
            while (index < lines.size && depth > 0) {
                val line = lines[index]
                if (depth == 1) {
                    val assignment = Regex("""^  ([a-z_]+) = (.*)$""")
                        .matchEntire(line)
                    if (assignment != null) {
                        assignments[assignment.groupValues[1]] =
                            assignment.groupValues[2]
                    }
                }
                depth += line.count { it == '{' }
                depth -= line.count { it == '}' }
                assertTrue(depth >= 0, "invalid $blockType block depth: $name")
                index += 1
            }
            assertEquals(0, depth, "unterminated $blockType block: $name")
            assertEquals(null, result.put(name, assignments), "duplicate $blockType: $name")
        }
        return result
    }

    private fun topLevelAssignments(text: String): Map<String, String> {
        var depth = 0
        val assignments = linkedMapOf<String, String>()
        text.lineSequence().forEach { line ->
            if (depth == 0) {
                val assignment = Regex("""^([a-z0-9_]+) = (.*)$""").matchEntire(line)
                if (assignment != null) {
                    assertEquals(
                        null,
                        assignments.put(
                            assignment.groupValues[1],
                            assignment.groupValues[2],
                        ),
                        "duplicate top-level assignment",
                    )
                }
            }
            depth += line.count { it == '{' }
            depth -= line.count { it == '}' }
            assertTrue(depth >= 0, "invalid effective configuration depth")
        }
        assertEquals(0, depth, "unterminated effective configuration block")
        return assignments
    }

    private fun nestedBlockAssignments(
        text: String,
        outerBlockType: String,
        outerBlockName: String,
        nestedBlockName: String,
    ): Map<String, String> {
        val lines = text.lines()
        val outerStart = lines.indexOf(
            "$outerBlockType $outerBlockName {",
        )
        assertTrue(
            outerStart >= 0,
            "missing $outerBlockType block: $outerBlockName",
        )
        var outerDepth = 1
        var index = outerStart + 1
        while (index < lines.size && outerDepth > 0) {
            val line = lines[index]
            if (outerDepth == 1 && line == "  $nestedBlockName {") {
                val assignments = linkedMapOf<String, String>()
                var nestedDepth = 1
                index += 1
                while (index < lines.size && nestedDepth > 0) {
                    val nestedLine = lines[index]
                    if (nestedDepth == 1) {
                        val assignment = Regex(
                            """^    ([a-z_]+) = (.*)$""",
                        ).matchEntire(nestedLine)
                        if (assignment != null) {
                            assignments[assignment.groupValues[1]] =
                                assignment.groupValues[2]
                        }
                    }
                    nestedDepth += nestedLine.count { it == '{' }
                    nestedDepth -= nestedLine.count { it == '}' }
                    assertTrue(
                        nestedDepth >= 0,
                        "invalid nested block depth: $nestedBlockName",
                    )
                    index += 1
                }
                assertEquals(
                    0,
                    nestedDepth,
                    "unterminated nested block: $nestedBlockName",
                )
                return assignments
            }
            outerDepth += line.count { it == '{' }
            outerDepth -= line.count { it == '}' }
            assertTrue(
                outerDepth >= 0,
                "invalid $outerBlockType block depth: $outerBlockName",
            )
            index += 1
        }
        throw AssertionError(
            "missing $nestedBlockName in $outerBlockType $outerBlockName",
        )
    }

    private fun portPublication(value: kotlinx.serialization.json.JsonElement): PortPublication {
        val port = value.jsonObject
        return PortPublication(
            hostIp = port.requiredString("host_ip"),
            published = port.requiredString("published"),
            target = port.requiredInt("target"),
            protocol = port.requiredString("protocol"),
            mode = port.requiredString("mode"),
        )
    }

    private fun mount(value: kotlinx.serialization.json.JsonElement): Mount {
        val mount = value.jsonObject
        assertEquals("bind", mount.requiredString("type"))
        return Mount(
            source = Path.of(mount.requiredString("source")).normalize(),
            target = mount.requiredString("target"),
            readOnly = mount["read_only"]?.jsonPrimitive?.boolean ?: false,
        )
    }

    private fun JsonObject.requiredObject(name: String): JsonObject =
        assertNotNull(this[name], "missing object: $name").jsonObject

    private fun JsonObject.requiredArray(name: String): JsonArray =
        assertNotNull(this[name], "missing array: $name").jsonArray

    private fun JsonObject.requiredString(name: String): String =
        assertNotNull(
            assertNotNull(this[name], "missing string: $name")
                .jsonPrimitive
                .contentOrNull,
            "non-string value: $name",
        )

    private fun JsonObject.requiredInt(name: String): Int =
        assertNotNull(this[name], "missing integer: $name").jsonPrimitive.int

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

    private data class PortPublication(
        val hostIp: String,
        val published: String,
        val target: Int,
        val protocol: String,
        val mode: String,
    )

    private data class Mount(
        val source: Path,
        val target: String,
        val readOnly: Boolean,
    )

    companion object {
        private const val OPERATOR_PROFILE = "dovecot-operator"
        private const val PINNED_DOVECOT_IMAGE =
            "dovecot/dovecot:2.4.1@" +
                "sha256:1296e0f1029cdd95e6849fb82f5d142a6e2a46218451773316cea678de75254b"
        private val COMPOSE_TIMEOUT = Duration.ofSeconds(10)
        private val OUTPUT_JOIN_TIMEOUT = Duration.ofSeconds(2)
        private const val MAX_COMPOSE_OUTPUT_BYTES = 1024 * 1024
        private val EXPECTED_OPERATOR_CONFIG = """
            dovecot_config_version = 2.4.1
            dovecot_storage_version = 2.4.0

            base_dir = /run/dovecot
            state_dir = /run/dovecot
            default_internal_user = vmail
            default_login_user = vmail
            default_internal_group = vmail

            protocols = imap
            auth_mechanisms = login
            auth_allow_cleartext = no
            auth_master_user_separator = *
            auth_username_format = %{user}

            passdb operator-master {
              driver = passwd-file
              passwd_file_path = /etc/dovecot/operator-auth/master-users
              master = yes
              result_success = continue
            }

            passdb deny-direct {
              driver = static
              deny = yes
              skip = authenticated
              fields {
                nopassword = yes
                nodelay = yes
              }
            }

            passdb eligible-target {
              driver = passwd-file
              passwd_file_path = /etc/dovecot/runtime/users
              skip = unauthenticated
              result_failure = continue-fail
              result_internalfail = return-fail
            }

            passdb deny-missing {
              driver = static
              deny = yes
              fields {
                nopassword = yes
                nodelay = yes
              }
            }

            userdb passwd-file {
              passwd_file_path = /etc/dovecot/runtime/users
              fields {
                uid:default = 1000
                gid:default = 1000
                home:default = /srv/vmail/%{user}
              }
            }

            mail_home = /srv/vmail/%{user}
            mail_driver = maildir
            mail_path = ~/Maildir
            mailbox_list_layout = index
            mailbox_list_utf8 = yes
            mail_utf8_extensions = yes
            mail_uid = vmail
            mail_gid = vmail

            namespace inbox {
              name = inbox
              type = private
              inbox = yes
              prefix = INBOX.
              separator = .
              namespace_list = yes
              subscriptions = yes

              mailbox Drafts {
                auto = create
                special_use = \Drafts
              }
              mailbox Sent {
                auto = create
                special_use = \Sent
              }
              mailbox Trash {
                auto = create
                special_use = \Trash
              }
            }

            ssl = yes
            ssl_server_cert_file = /etc/dovecot/ssl/tls.crt
            ssl_server_key_file = /etc/dovecot/ssl/tls.key

            service imap-login {
              chroot =
              process_min_avail = 1
              inet_listener imap {
                port = 0
              }
              inet_listener imaps {
                port = 31993
                ssl = yes
              }
            }

            log_path = /dev/stdout
            info_log_path = /dev/stdout
            debug_log_path = /dev/stdout
            auth_debug = yes
            auth_verbose = yes
            auth_verbose_passwords = no
            mail_debug = yes
        """.trimIndent() + "\n"
    }
}

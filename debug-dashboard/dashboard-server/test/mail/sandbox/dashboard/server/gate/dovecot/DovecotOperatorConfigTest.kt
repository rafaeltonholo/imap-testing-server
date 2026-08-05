package mail.sandbox.dashboard.server.gate.dovecot

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.time.Duration
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
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
    private val baseComposePath = repositoryRoot.resolve("docker-compose.yml")
    private val operatorConfigPath = repositoryRoot.resolve("config/operator/dovecot.conf")
    private val operatorHealthcheckPath = repositoryRoot.resolve(
        "config/operator/healthcheck.sh",
    )
    private val postfixEntrypointPath = repositoryRoot.resolve(
        "postfix/entrypoint.sh",
    )
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
    private val operatorTransportPlanPath = repositoryRoot.resolve(
        "docs/superpowers/plans/2026-07-30-dovecot-operator-stdio-transport.md",
    )
    private val operatorTransportDesignPath = repositoryRoot.resolve(
        "docs/superpowers/specs/2026-07-30-dovecot-operator-stdio-transport-design.md",
    )
    private val startupLiveTestPath = repositoryRoot.resolve(
        "debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/" +
            "server/gate/dovecot/DovecotOperatorStartupLiveTest.kt",
    )
    private val isolationProtocolProofPath = repositoryRoot.resolve(
        "debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/" +
            "server/gate/dovecot/DovecotIsolationProtocolProof.kt",
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
    fun operatorAuthenticationFailuresDoNotAddReplyDelayOrPenalty() {
        val assignments = topLevelAssignments(
            Files.readString(operatorConfigPath),
        )

        assertEquals(
            "0s",
            assignments["auth_failure_delay"],
            "Expected operator failures not to enqueue a reply delay or " +
                "increment Dovecot's per-source penalty",
        )
    }

    @Test
    fun operatorUserIpCapacityMatchesTrackedSessionCapacity() {
        val assignments = topLevelAssignments(
            Files.readString(operatorConfigPath),
        )

        assertEquals(
            "16",
            assignments["mail_max_userip_connections"],
            "The operator provider must admit every one of the 16 tracked " +
                "same-user loopback sessions",
        )
    }

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
        assertEquals("2.4.4", assignments.getValue("dovecot_config_version"))
        assertEquals("2.4.3", assignments.getValue("dovecot_storage_version"))
        assertEquals("maildir", assignments.getValue("mail_driver"))
        assertEquals("~/Maildir", assignments.getValue("mail_path"))
        assertEquals("index", assignments.getValue("mailbox_list_layout"))
        assertEquals("yes", assignments["mailbox_list_utf8"], assignments.toString())
        assertEquals("yes", assignments.getValue("mail_utf8_extensions"))
        assertEquals("vmail", assignments.getValue("mail_uid"))
        assertEquals("vmail", assignments.getValue("mail_gid"))
    }

    fun firstNonMasterPassdbCannotBeUnauthenticatedSkip() {
        val passdbs = topLevelNamedBlocks(effectiveOperatorConfig(), "passdb")
        val firstNonMaster = passdbs.entries.first { it.value["master"] != "yes" }

        assertEquals(
            "deny-direct",
            firstNonMaster.key,
            "Dovecot 2.4.4 auth_preinit silently omits a leading non-master " +
                "passdb with skip=unauthenticated",
        )
        assertEquals(
            "authenticated",
            firstNonMaster.value["skip"],
            "The preinit anchor must deny direct logins but be skipped after " +
                "the master password is verified",
        )
    }

    fun imapsListenerMirrorsServiceUsersInsteadOfFallingBackToImageIdentities() {
        val effective = effectiveOperatorConfig()
        val global = topLevelAssignments(effective)
        val listener = nestedBlockAssignments(
            text = effective,
            outerBlockType = "service",
            outerBlockName = "imap-login",
            nestedBlockName = "inet_listener imaps",
        )
        val serviceUserKeys = setOf(
            "default_internal_group",
            "default_internal_user",
            "default_login_user",
        )

        assertEquals(
            global.filterKeys(serviceUserKeys::contains),
            listener.filterKeys(serviceUserKeys::contains),
            "The 2.4 listener-filter context must mirror the global vmail " +
                "identities instead of falling back to absent image users",
        )
        assertEquals("127.0.0.1", listener.getValue("listen"))
        assertEquals("31993", listener.getValue("port"))
        assertEquals("yes", listener.getValue("ssl"))
    }

    fun operatorEndpointRejectsThePlainAuthzidMasterFormByMechanism() {
        val configured = Files.readString(operatorConfigPath)
        val mutated = configured.replace(
            "auth_mechanisms = login\n",
            "auth_mechanisms = plain login\n",
        )
        assertTrue(mutated != configured, "LOGIN-only operator setting was not found")

        assertLoginOnlyCombinedMasterForm(effectiveOperatorConfig())
        assertFailsWith<AssertionError> {
            assertLoginOnlyCombinedMasterForm(mutated)
        }
    }

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
            val mutatedEffective = ordinaryConfigSource(mutatedConfig)
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

    fun baseComposeKeepsOperatorBehindExplicitProfileAndScopedEvidenceSelectsIt() {
        val configured = Files.readString(baseComposePath)
        val serviceSection = configured
            .substringAfter("services:\n")
            .substringBefore("\nnetworks:\n")
        val configuredServices = Regex("""(?m)^  ([a-z0-9-]+):$""")
            .findAll(serviceSection)
            .map { it.groupValues[1] }
            .toSet()
        assertEquals(
            setOf(
                "dovecot",
                "dovecot-operator",
                "postfix",
                "oauth2-mock",
                "stalwart",
            ),
            configuredServices,
        )
        val operatorSource = serviceSection
            .substringAfter("  dovecot-operator:\n")
            .substringBefore("\n  postfix:\n")
        assertTrue(
            "    profiles:\n      - $OPERATOR_PROFILE\n" in operatorSource,
            "The base operator must remain behind its explicit profile",
        )

        val activatedServices = resolvedOperatorCompose().requiredObject("services")
        assertEquals(
            setOf("dovecot", "postfix", "oauth2-mock", "dovecot-operator"),
            activatedServices.keys,
        )
        assertEquals(
            listOf(OPERATOR_PROFILE),
            activatedServices.requiredObject("dovecot-operator")
                .requiredArray("profiles")
                .map { it.jsonPrimitive.content },
        )
    }

    fun resolvedBaseAndProofComposeKeepTheOperatorControlPlaneOnly() {
        val base = resolvedOperatorCompose()
        val proof = resolvedProofCompose()

        listOf(base, proof).forEach(::assertPrivateOperatorTopology)
        assertBaseOrdinaryTopology(base)
        assertProofOrdinaryTopology(proof)

        val proofSource = Files.readString(proofComposePath)
        assertTrue(
            "    ports: !override []\n" in proofSource,
            "The proof must explicitly clear any future base publication",
        )
        listOf(
            Files.readString(baseComposePath),
            proofSource,
            base.toString(),
            proof.toString(),
        ).forEach { model ->
            assertFalse(
                "2993" in model,
                "Forbidden host port 2993 must be absent from Compose sources and models",
            )
        }
    }

    fun topologyAuditorRejectsEveryForbiddenBaseAndProofMutation() {
        listOf(
            "base" to resolvedOperatorCompose(),
            "proof" to resolvedProofCompose(),
        ).forEach { (label, resolved) ->
            val mutations = listOf(
                "expose" to mutateService(resolved, "dovecot-operator") { operator ->
                    JsonObject(operator + ("expose" to JsonArray(listOf(JsonPrimitive("31993")))))
                },
                "host network mode" to
                    mutateService(resolved, "dovecot-operator") { operator ->
                        JsonObject(operator + ("network_mode" to JsonPrimitive("host")))
                    },
                "extra default operator network" to
                    mutateService(resolved, "dovecot-operator") { operator ->
                        val networks = operator.requiredObject("networks")
                        JsonObject(
                            operator +
                                (
                                    "networks" to
                                        JsonObject(networks + ("default" to JsonObject(emptyMap())))
                                    ),
                        )
                    },
                "second ingress member" to mutateService(resolved, "dovecot") { ordinary ->
                    val networks = ordinary.requiredObject("networks")
                    JsonObject(
                        ordinary +
                            (
                                "networks" to
                                    JsonObject(
                                        networks +
                                            ("operator-ingress" to JsonObject(emptyMap())),
                                    )
                                ),
                    )
                },
            )

            mutations.forEach { (mutation, mutated) ->
                assertTrue(
                    mutated != resolved,
                    "$label $mutation mutation did not land",
                )
                assertFailsWith<AssertionError>(
                    message = "$label $mutation mutation escaped the topology auditor",
                ) {
                    assertPrivateOperatorTopology(mutated)
                }
            }
        }
    }

    @Test
    fun operatorIngressDocumentationRequiresAQuietOperationalHealthcheck() {
        val task4 = Files.readString(operatorTransportPlanPath)
            .substringAfter("## Task 4:")
            .substringBefore("## Task 5:")
            .normalizeDocumentationWhitespace()
        val amendment = Files.readString(operatorTransportDesignPath)
            .substringAfter("### Compose topology")
            .substringBefore("## Failure Semantics")
            .normalizeDocumentationWhitespace()

        listOf(task4, amendment).forEach { document ->
            assertTrue("`operator-ingress.internal" in document)
            assertTrue("`/proc/net/tcp`" in document)
            assertTrue("`/proc/net/tcp6`" in document)
            assertTrue("`0100007F:7CF9`" in document)
            assertTrue(
                "exactly one" in document || "count exactly one" in document,
            )
            assertTrue("sole" in document)
        }
        assertTrue("retain all existing" in amendment)
        assertTrue("read-only runtime, operator-auth, and TLS mounts" in amendment)
    }

    @Test
    fun operatorAuthDocumentationRequiresPreinitSafeFourPassdbChain() {
        val completeDesign = Files.readString(designSpecPath)
        val plan = Files.readString(implementationPlanPath)
            .substringAfter("## Task 5:")
            .substringBefore("## Task 6:")
            .normalizeDocumentationWhitespace()
        val gate0cSpec = Files.readString(designSpecPath)
            .substringAfter("### Gate 0C — Dovecot operator access")
            .substringBefore("### Gate 1 — Live parity suite")
            .normalizeDocumentationWhitespace()
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
        assertTrue(
            "https://doc.dovecot.org/2.4.4/core/config/auth/passdb.html" in
                completeDesign,
        )
        assertTrue(
            "https://doc.dovecot.org/2.4.4/core/config/auth/master_users.html" in
                completeDesign,
        )
        assertFalse("https://doc.dovecot.org/2.4.1/core/config/auth/" in completeDesign)
    }

    @Test
    fun task5LiveProofUsesTheBoundedExchangeBeforeCombinedMasterLogin() {
        val source = Files.readString(startupLiveTestPath)
        val addEligible = source.indexOf("addEligibleTarget(")
        val directLogin = source.indexOf(
            "authenticateBareTarget(",
        )
        val plainAuthzid = source.indexOf(
            "authenticatePlainAuthzidMaster(",
        )
        val masterLogin = source.indexOf(
            "val result = probe.probe(target, credential)",
        )

        assertTrue(addEligible >= 0)
        assertTrue(directLogin > addEligible)
        assertTrue(plainAuthzid > directLogin)
        assertTrue(masterLogin > plainAuthzid)
        assertTrue("live.operatorRuntime.probe()" in source)
        assertTrue("live.operatorExchange" in source)
        assertTrue("EligibilityPassword" in source)
        assertTrue("credentialBuffers.all" in source)
        val retiredSocketFactory =
            "JvmJsseDovecotOperator" + "TransportFactory"
        assertFalse(retiredSocketFactory in source)
        assertFalse("readBoundedLiveLine(" in source)
        assertFalse("AUTHENTICATE LOGIN" in source)
        assertFalse("decodeToString" in source)
    }

    @Test
    fun task5OrdinaryImapProofUsesOnlyItsFrozenProfileEndpoint() {
        val source = Files.readString(isolationProtocolProofPath)

        assertEquals(
            1,
            source.windowed(
                "ordinaryImapsPort = profile.ordinaryImapsPort".length,
            ).count {
                it == "ordinaryImapsPort = profile.ordinaryImapsPort"
            },
        )
        assertFalse("forbiddenOperatorHostPort" in source)
        assertFalse(
            Regex(
                """fun\s+requireOrdinaryImapRejected\s*\(\s*port\s*:""",
            ).containsMatchIn(source),
        )
        assertFalse(
            Regex(
                """fun\s+ordinaryImapLogin\s*\(\s*port\s*:""",
            ).containsMatchIn(source),
        )
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
            "`127.0.0.1:1995` → `31995`",
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
        assertTrue("dedicated internal bridge" in serviceMap)
        assertTrue("None" in serviceMap)
        assertFalse("Target state pending confirmation and implementation" in serviceMap)
        assertFalse("`127.0.0.1:2993` → `31993`" in serviceMap)
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
                    source = repositoryRoot.resolve("config/operator/healthcheck.sh"),
                    target = "/usr/local/bin/operator-healthcheck",
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

    fun resolvedComposePinsBoundedQuietOperationalHealthcheck() {
        val operator = resolvedOperatorCompose()
            .requiredObject("services")
            .requiredObject("dovecot-operator")
        val health = operator.requiredObject("healthcheck")

        assertEquals(
            listOf("CMD", "/usr/local/bin/operator-healthcheck"),
            health.requiredArray("test").map { it.jsonPrimitive.content },
        )
        assertEquals("5s", health.requiredString("interval"))
        assertEquals("3s", health.requiredString("timeout"))
        assertEquals("10s", health.requiredString("start_period"))
        assertEquals(5, health.requiredInt("retries"))
        assertFalse("environment" in operator)

        assertTrue(Files.isRegularFile(operatorHealthcheckPath))
        assertTrue(Files.isExecutable(operatorHealthcheckPath))
        assertEquals(
            PosixFilePermissions.fromString("rwxr-xr-x"),
            Files.getPosixFilePermissions(operatorHealthcheckPath),
        )
        val source = Files.readString(operatorHealthcheckPath)
        assertTrue(source.startsWith("#!/bin/sh\n"))
        assertTrue("doveadm service status auth" in source)
        assertTrue("doveadm service status imap-login" in source)
        assertTrue("DOVECOT_OPERATOR_PROC_TCP" in source)
        assertTrue("DOVECOT_OPERATOR_PROC_TCP6" in source)
        listOf("grep", "awk", "sed", "ps", "pgrep", "procps").forEach { utility ->
            assertFalse(
                Regex(
                    "(?m)(?:^|[\\s;&|()])${Regex.escape(utility)}" +
                        "(?=\$|[\\s;&|()])",
                ).containsMatchIn(source),
                "operator healthcheck must not require $utility",
            )
        }
    }

    @Test
    fun postfixEntrypointCreatesPinned310ChrootEtcBeforeDnsCopies() {
        val source = Files.readString(postfixEntrypointPath)

        fun assertChrootPreparation(candidate: String) {
            val createChrootEtc = assertNotNull(
                Regex("""(?m)^mkdir -p /var/spool/postfix/etc$""")
                    .find(candidate),
                "Postfix 3.10.12 does not create /var/spool/postfix/etc " +
                    "before the entrypoint copies resolver files into that chroot",
            )
            val firstChrootCopy = assertNotNull(
                Regex(
                    """(?m)^cp /etc/resolv\.conf """ +
                        """/var/spool/postfix/etc/resolv\.conf$""",
                ).find(candidate),
                "resolver copy contract changed",
            )

            assertTrue(
                createChrootEtc.range.first < firstChrootCopy.range.first,
                "the chroot etc directory must exist before the first copy",
            )
        }

        assertChrootPreparation(source)
        val commentedOut = source.replace(
            "\nmkdir -p /var/spool/postfix/etc\n",
            "\n# mkdir -p /var/spool/postfix/etc\n",
        )
        assertTrue(commentedOut != source, "mkdir command mutation did not land")
        assertFailsWith<AssertionError> {
            assertChrootPreparation(commentedOut)
        }
    }

    @Test
    fun operatorHealthcheckAcceptsOnlyHealthyServiceStatus() {
        val healthy = serviceStatus()
        val invalidStatuses = listOf(
            "missing process_count" to "throttle_secs: 0\ndoveadm_stop: n",
            "zero process_count" to serviceStatus(processCount = "0"),
            "nonnumeric process_count" to serviceStatus(processCount = "one"),
            "duplicate process_count" to "$healthy\nprocess_count: 2",
            "missing throttle_secs" to "process_count: 1\ndoveadm_stop: n",
            "nonzero throttle_secs" to serviceStatus(throttleSecs = "1"),
            "duplicate throttle_secs" to "$healthy\nthrottle_secs: 0",
            "missing doveadm_stop" to "process_count: 1\nthrottle_secs: 0",
            "stopped doveadm" to serviceStatus(doveadmStop = "y"),
            "duplicate doveadm_stop" to "$healthy\ndoveadm_stop: n",
            "malformed required key" to
                healthy.replace("process_count: 1", "process count: 1"),
            "duplicate service key" to "$healthy\nname: duplicate",
            "malformed status row" to "$healthy\nmalformed",
            "empty status" to "",
        )

        val valid = runOperatorHealthcheck()
        assertEquals(0, valid.exitCode, valid.stderr)
        assertEquals("", valid.stdout)
        assertEquals("", valid.stderr)

        invalidStatuses.forEach { (name, status) ->
            assertTrue(
                runOperatorHealthcheck(authStatus = status).exitCode != 0,
                "auth: $name",
            )
            assertTrue(
                runOperatorHealthcheck(imapLoginStatus = status).exitCode != 0,
                "imap-login: $name",
            )
        }
        assertTrue(runOperatorHealthcheck(failingService = "auth").exitCode != 0)
        assertTrue(runOperatorHealthcheck(failingService = "imap-login").exitCode != 0)
    }

    @Test
    fun operatorHealthcheckAcceptsPinnedDovecot244ProcHeaders() {
        val result = runOperatorHealthcheck(
            tcpHeader = PROC_NET_HEADER,
            tcp6Header = DOVECOT_244_PROC_NET_TCP6_HEADER,
        )

        assertEquals(0, result.exitCode, result.stderr)
        assertEquals("", result.stdout)
        assertEquals("", result.stderr)
    }

    @Test
    fun operatorHealthcheckAcceptsOnlyOneIpv4LoopbackListenSocket() {
        val fixtures = listOf(
            ListenerFixture(
                name = "exact plus irrelevant",
                expected = true,
                tcpRows = listOf(
                    procNetRow(slot = 0, local = "0100007F:7CF9", state = "0A"),
                    procNetRow(slot = 1, local = "00000000:008F", state = "0A"),
                ),
                tcp6Rows = listOf(
                    procNetRow(
                        slot = 0,
                        local = "00000000000000000000000000000000:008F",
                        state = "0A",
                    ),
                ),
            ),
            ListenerFixture("absent", false, emptyList(), emptyList()),
            ListenerFixture(
                "wildcard",
                false,
                listOf(procNetRow(0, "00000000:7CF9", "0A")),
                emptyList(),
            ),
            ListenerFixture(
                "IPv6",
                false,
                emptyList(),
                listOf(
                    procNetRow(
                        0,
                        "00000000000000000000000001000000:7CF9",
                        "0A",
                    ),
                ),
            ),
            ListenerFixture(
                "duplicate",
                false,
                listOf(
                    procNetRow(0, "0100007F:7CF9", "0A"),
                    procNetRow(1, "0100007F:7CF9", "0A"),
                ),
                emptyList(),
            ),
            ListenerFixture(
                "duplicate slot",
                false,
                listOf(
                    procNetRow(0, "0100007F:7CF9", "0A"),
                    procNetRow(0, "00000000:008F", "0A"),
                ),
                emptyList(),
            ),
            ListenerFixture(
                "unterminated duplicate",
                false,
                listOf(
                    procNetRow(0, "0100007F:7CF9", "0A"),
                    procNetRow(1, "00000000:7CF9", "0A"),
                ),
                emptyList(),
                tcpFinalNewline = false,
            ),
            ListenerFixture(
                "exact plus wildcard",
                false,
                listOf(
                    procNetRow(0, "0100007F:7CF9", "0A"),
                    procNetRow(1, "00000000:7CF9", "0A"),
                ),
                emptyList(),
            ),
            ListenerFixture(
                "exact plus IPv6",
                false,
                listOf(procNetRow(0, "0100007F:7CF9", "0A")),
                listOf(
                    procNetRow(
                        0,
                        "00000000000000000000000001000000:7CF9",
                        "0A",
                    ),
                ),
            ),
            ListenerFixture(
                "exact plus lowercase wildcard",
                false,
                listOf(
                    procNetRow(0, "0100007F:7CF9", "0A"),
                    procNetRow(1, "00000000:7cf9", "0a"),
                ),
                emptyList(),
            ),
            ListenerFixture(
                "exact plus malformed",
                false,
                listOf(
                    procNetRow(0, "0100007F:7CF9", "0A"),
                    "  1: malformed",
                ),
                emptyList(),
            ),
            ListenerFixture(
                "malformed slot",
                false,
                listOf(
                    procNetRow(0, "0100007F:7CF9", "0A"),
                    procNetRow(1, "00000000:008F", "0A")
                        .replace("  1:", "  slot:"),
                ),
                emptyList(),
            ),
            ListenerFixture(
                "exact plus malformed local endpoint",
                false,
                listOf(
                    procNetRow(0, "0100007F:7CF9", "0A"),
                    procNetRow(1, "NOT_AN_ENDPOINT", "0A"),
                ),
                emptyList(),
            ),
            ListenerFixture(
                "exact plus malformed state",
                false,
                listOf(
                    procNetRow(0, "0100007F:7CF9", "0A"),
                    procNetRow(1, "00000000:008F", "ZZ"),
                ),
                emptyList(),
            ),
            ListenerFixture(
                "wrong state",
                false,
                listOf(procNetRow(0, "0100007F:7CF9", "01")),
                emptyList(),
            ),
            ListenerFixture(
                "malformed remote endpoint",
                false,
                listOf(
                    procNetRow(0, "0100007F:7CF9", "0A")
                        .replace("00000000:0000", "NOT_REMOTE"),
                ),
                emptyList(),
            ),
            ListenerFixture(
                "malformed queue",
                false,
                listOf(
                    procNetRow(0, "0100007F:7CF9", "0A"),
                    procNetRow(1, "00000000:008F", "0A")
                        .replace(" 00000000:00000000 ", " INVALID_QUEUE "),
                ),
                emptyList(),
            ),
            ListenerFixture(
                "malformed timer",
                false,
                listOf(
                    procNetRow(0, "0100007F:7CF9", "0A"),
                    procNetRow(1, "00000000:008F", "0A")
                        .replace(" 00:00000000 ", " INVALID_TIMER "),
                ),
                emptyList(),
            ),
            ListenerFixture(
                "malformed retransmit",
                false,
                listOf(
                    procNetRow(0, "0100007F:7CF9", "0A"),
                    procNetRow(1, "00000000:008F", "0A")
                        .replace(" 00000000 1000 ", " INVALID_RETRANSMIT 1000 "),
                ),
                emptyList(),
            ),
            ListenerFixture(
                "malformed uid",
                false,
                listOf(
                    procNetRow(0, "0100007F:7CF9", "0A"),
                    procNetRow(1, "00000000:008F", "0A")
                        .replace(" 1000 0 1 1 ", " UID 0 1 1 "),
                ),
                emptyList(),
            ),
            ListenerFixture(
                "malformed timeout",
                false,
                listOf(
                    procNetRow(0, "0100007F:7CF9", "0A"),
                    procNetRow(1, "00000000:008F", "0A")
                        .replace(" 1000 0 1 1 ", " 1000 TIMEOUT 1 1 "),
                ),
                emptyList(),
            ),
            ListenerFixture(
                "malformed inode",
                false,
                listOf(
                    procNetRow(0, "0100007F:7CF9", "0A"),
                    procNetRow(1, "00000000:008F", "0A")
                        .replace(" 1000 0 1 1 ", " 1000 0 INODE 1 "),
                ),
                emptyList(),
            ),
            ListenerFixture(
                "IPv6 legacy remote header",
                false,
                listOf(procNetRow(0, "0100007F:7CF9", "0A")),
                emptyList(),
                tcp6Header = PROC_NET_HEADER,
            ),
            ListenerFixture(
                "malformed header",
                false,
                listOf(procNetRow(0, "0100007F:7CF9", "0A")),
                emptyList(),
                tcpHeader = "malformed header",
            ),
        )

        fixtures.forEach { fixture ->
            assertEquals(
                fixture.expected,
                runOperatorHealthcheck(
                    tcpRows = fixture.tcpRows,
                    tcp6Rows = fixture.tcp6Rows,
                    tcpHeader = fixture.tcpHeader,
                    tcp6Header = fixture.tcp6Header,
                    tcpFinalNewline = fixture.tcpFinalNewline,
                    tcp6FinalNewline = fixture.tcp6FinalNewline,
                ).exitCode == 0,
                fixture.name,
            )
        }
        assertTrue(runOperatorHealthcheck(omitTcp = true).exitCode != 0)
        assertTrue(runOperatorHealthcheck(omitTcp6 = true).exitCode != 0)
    }

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
        assertFalse(clearProfile in mutated)
    }

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
                        target = 31995,
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
            services
                .filterKeys { it != "dovecot-operator" }
                .mapValues { (_, value) ->
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
            repositoryRoot.resolve("config/operator/healthcheck.sh").toString(),
            source("dovecot-operator", "/usr/local/bin/operator-healthcheck"),
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

    private fun assertPrivateOperatorTopology(resolved: JsonObject) {
        val services = resolved.requiredObject("services")
        val operator = services.requiredObject("dovecot-operator")

        assertEquals(PINNED_DOVECOT_IMAGE, operator.requiredString("image"))
        assertEquals("unless-stopped", operator.requiredString("restart"))
        listOf("ports", "expose", "network_mode").forEach { forbidden ->
            assertFalse(
                forbidden in operator,
                "dovecot-operator must not define $forbidden",
            )
        }
        assertEquals(
            setOf("operator-ingress"),
            operator.requiredObject("networks").keys,
        )
        assertTrue(
            resolved.requiredObject("networks")
                .requiredObject("operator-ingress")
                .requiredBoolean("internal"),
            "operator-ingress must be an internal bridge",
        )
        assertEquals(
            setOf("dovecot-operator"),
            services
                .filterValues { service ->
                    "operator-ingress" in service.jsonObject.requiredObject("networks")
                }
                .keys,
            "dovecot-operator must be the sole operator-ingress member",
        )
    }

    private fun assertBaseOrdinaryTopology(resolved: JsonObject) {
        val services = resolved.requiredObject("services")
        val ordinary = services.filterKeys { it != "dovecot-operator" }
        assertEquals(
            mapOf(
                "dovecot" to listOf(
                    PortPublication("127.0.0.1", "1143", 31143, "tcp", "ingress"),
                    PortPublication("127.0.0.1", "1993", 31993, "tcp", "ingress"),
                    PortPublication("127.0.0.1", "1110", 31110, "tcp", "ingress"),
                    PortPublication("127.0.0.1", "1995", 31995, "tcp", "ingress"),
                ),
                "postfix" to listOf(
                    PortPublication("127.0.0.1", "1025", 25, "tcp", "ingress"),
                    PortPublication("127.0.0.1", "1465", 465, "tcp", "ingress"),
                    PortPublication("127.0.0.1", "1587", 587, "tcp", "ingress"),
                ),
                "oauth2-mock" to listOf(
                    PortPublication("127.0.0.1", "8080", 8080, "tcp", "ingress"),
                ),
            ),
            ordinary.mapValues { (_, service) ->
                service.jsonObject.requiredArray("ports").map(::portPublication)
            },
        )
        ordinary.forEach { (name, service) ->
            assertEquals(
                setOf("default"),
                service.jsonObject.requiredObject("networks").keys,
                "$name ordinary network contract changed",
            )
        }
    }

    private fun assertProofOrdinaryTopology(resolved: JsonObject) {
        val services = resolved.requiredObject("services")
        assertEquals(
            setOf("dovecot", "dovecot-operator", "postfix", "oauth2-mock"),
            services.keys,
        )
        assertEquals(
            mapOf(
                "dovecot" to listOf(
                    PortPublication("127.0.0.1", "1993", 31993, "tcp", "ingress"),
                    PortPublication("127.0.0.1", "21995", 31995, "tcp", "ingress"),
                ),
                "postfix" to listOf(
                    PortPublication("127.0.0.1", "21025", 25, "tcp", "ingress"),
                ),
                "oauth2-mock" to listOf(
                    PortPublication("127.0.0.1", "28080", 8080, "tcp", "ingress"),
                ),
            ),
            services
                .filterKeys { it != "dovecot-operator" }
                .mapValues { (_, service) ->
                    service.jsonObject.requiredArray("ports").map(::portPublication)
                },
        )
        services
            .filterKeys { it != "dovecot-operator" }
            .forEach { (name, service) ->
                assertEquals(
                    setOf("default"),
                    service.jsonObject.requiredObject("networks").keys,
                    "$name proof network contract changed",
                )
            }
        assertEquals(
            setOf("default", "operator-ingress"),
            resolved.requiredObject("networks").keys,
        )
    }

    private fun mutateService(
        resolved: JsonObject,
        serviceName: String,
        mutation: (JsonObject) -> JsonObject,
    ): JsonObject {
        val services = resolved.requiredObject("services")
        val original = services.requiredObject(serviceName)
        val mutated = mutation(original)
        assertTrue(mutated != original, "$serviceName mutation did not land")
        return JsonObject(
            resolved +
                (
                    "services" to
                        JsonObject(services + (serviceName to mutated))
                    ),
        )
    }

    private fun String.normalizeDocumentationWhitespace(): String =
        replace(Regex("""\s+"""), " ").trim()

    private fun procNetRow(slot: Int, local: String, state: String): String {
        val remoteAddress = if (local.substringBefore(':').length == 32) {
            "00000000000000000000000000000000:0000"
        } else {
            "00000000:0000"
        }
        return "  $slot: $local $remoteAddress $state " +
            "00000000:00000000 00:00000000 00000000 1000 0 1 1 " +
            "0000000000000000 100 0 0 10 0"
    }

    private fun serviceStatus(
        processCount: String = "1",
        throttleSecs: String = "0",
        doveadmStop: String = "n",
    ): String = listOf(
        "name: fixture",
        "process_count: $processCount",
        "process_avail: 0",
        "throttle_secs: $throttleSecs",
        "doveadm_stop: $doveadmStop",
    ).joinToString("\n")

    private fun runOperatorHealthcheck(
        authStatus: String = serviceStatus(),
        imapLoginStatus: String = serviceStatus(),
        failingService: String = "",
        tcpRows: List<String> = listOf(
            procNetRow(0, "0100007F:7CF9", "0A"),
            procNetRow(1, "00000000:008F", "0A"),
        ),
        tcp6Rows: List<String> = listOf(
            procNetRow(
                0,
                "00000000000000000000000000000000:008F",
                "0A",
            ),
        ),
        tcpHeader: String = PROC_NET_HEADER,
        tcp6Header: String = DOVECOT_244_PROC_NET_TCP6_HEADER,
        tcpFinalNewline: Boolean = true,
        tcp6FinalNewline: Boolean = true,
        omitTcp: Boolean = false,
        omitTcp6: Boolean = false,
    ): HealthcheckResult {
        assertTrue(
            Files.isRegularFile(operatorHealthcheckPath),
            "missing operator healthcheck script",
        )
        assertTrue(
            Files.isExecutable(operatorHealthcheckPath),
            "operator healthcheck script must be executable",
        )
        val directory = Files.createTempDirectory("dovecot-operator-health-")
        val bin = directory.resolve("bin")
        val fakeDoveadm = bin.resolve("doveadm")
        val tcp = directory.resolve("tcp")
        val tcp6 = directory.resolve("tcp6")
        try {
            Files.createDirectory(bin)
            Files.writeString(
                fakeDoveadm,
                """
                #!/bin/sh
                case "${'$'}1:${'$'}2:${'$'}3" in
                  service:status:auth)
                    case "${'$'}{FAKE_DOVEADM_FAIL:-}" in auth) exit 23 ;; esac
                    printf '%s\n' "${'$'}FAKE_DOVEADM_AUTH"
                    ;;
                  service:status:imap-login)
                    case "${'$'}{FAKE_DOVEADM_FAIL:-}" in imap-login) exit 23 ;; esac
                    printf '%s\n' "${'$'}FAKE_DOVEADM_IMAP_LOGIN"
                    ;;
                  *)
                    exit 24
                    ;;
                esac
                """.trimIndent() + "\n",
            )
            Files.setPosixFilePermissions(
                fakeDoveadm,
                PosixFilePermissions.fromString("rwx------"),
            )
            if (!omitTcp) {
                writeProcNetFixture(tcp, tcpHeader, tcpRows, tcpFinalNewline)
            }
            if (!omitTcp6) {
                writeProcNetFixture(tcp6, tcp6Header, tcp6Rows, tcp6FinalNewline)
            }

            val process = ProcessBuilder(operatorHealthcheckPath.toString())
                .apply {
                    environment().clear()
                    environment()["PATH"] = bin.toString()
                    environment()["FAKE_DOVEADM_AUTH"] = authStatus
                    environment()["FAKE_DOVEADM_IMAP_LOGIN"] = imapLoginStatus
                    environment()["FAKE_DOVEADM_FAIL"] = failingService
                    environment()["DOVECOT_OPERATOR_PROC_TCP"] = tcp.toString()
                    environment()["DOVECOT_OPERATOR_PROC_TCP6"] = tcp6.toString()
                }
                .start()
            try {
                assertTrue(
                    process.waitFor(OUTPUT_JOIN_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS),
                    "operator healthcheck fixture timed out",
                )
                return HealthcheckResult(
                    exitCode = process.exitValue(),
                    stdout = process.inputStream.readBytes().toString(StandardCharsets.UTF_8),
                    stderr = process.errorStream.readBytes().toString(StandardCharsets.UTF_8),
                )
            } finally {
                process.destroyForcibly()
            }
        } finally {
            Files.deleteIfExists(tcp)
            Files.deleteIfExists(tcp6)
            Files.deleteIfExists(fakeDoveadm)
            Files.deleteIfExists(bin)
            Files.deleteIfExists(directory)
        }
    }

    private fun writeProcNetFixture(
        path: Path,
        header: String,
        rows: List<String>,
        finalNewline: Boolean,
    ) {
        Files.writeString(
            path,
            (listOf(header) + rows).joinToString(
                separator = "\n",
                postfix = if (finalNewline) "\n" else "",
            ),
        )
    }

    private fun resolvedOperatorCompose(): JsonObject {
        val output = readProviderEvidence(BASE_COMPOSE_EVIDENCE)
        return Json.parseToJsonElement(output).jsonObject
    }

    private fun resolvedProofCompose(): JsonObject {
        val output = readProviderEvidence(PROOF_COMPOSE_EVIDENCE)
        return Json.parseToJsonElement(output).jsonObject
    }

    private fun effectiveOperatorConfig(): String =
        readProviderEvidence(OPERATOR_DOVECONF_EVIDENCE)

    private fun effectiveOrdinaryConfig(): String =
        readProviderEvidence(ORDINARY_DOVECONF_EVIDENCE)

    private fun ordinaryConfigSource(configDirectory: Path): String =
        Files.list(configDirectory).use { entries ->
            entries
                .filter { path ->
                    Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                }
                .sorted()
                .map(Files::readString)
                .toList()
                .joinToString(separator = "\n")
        }

    private fun readProviderEvidence(fileName: String): String {
        assertTrue(fileName in PROVIDER_EVIDENCE_FILES)
        val root = requiredProviderEvidenceRoot()
        val path = root.resolve(fileName)
        assertEquals(root, path.parent)
        assertTrue(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
        assertFalse(Files.isSymbolicLink(path))
        assertEquals(
            PosixFilePermissions.fromString("rw-------"),
            Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS),
        )
        val size = Files.size(path)
        assertTrue(size in 1L..MAX_PROVIDER_EVIDENCE_BYTES.toLong())
        val bytes = Files.readAllBytes(path)
        try {
            assertEquals(size, bytes.size.toLong())
            assertTrue(bytes.size <= MAX_PROVIDER_EVIDENCE_BYTES)
            return bytes.toString(StandardCharsets.UTF_8)
        } finally {
            bytes.fill(0)
        }
    }

    private fun requiredProviderEvidenceRoot(): Path {
        val configured = System.getenv(PROVIDER_EVIDENCE_ROOT_ENV)
            ?: error(
                "Provider evidence is available only inside the checked lifecycle",
            )
        val expected = repositoryRoot.resolve(
            "debug-dashboard/.runtime/task5-proof/provider-evidence",
        ).toAbsolutePath().normalize()
        val actual = Path.of(configured).toAbsolutePath().normalize()
        assertEquals(expected, actual)
        assertTrue(Files.isDirectory(actual, LinkOption.NOFOLLOW_LINKS))
        assertFalse(Files.isSymbolicLink(actual))
        assertEquals(
            PosixFilePermissions.fromString("rwx------"),
            Files.getPosixFilePermissions(actual, LinkOption.NOFOLLOW_LINKS),
        )
        return actual
    }

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

    private fun portPublication(value: JsonElement): PortPublication {
        val port = value.jsonObject
        return PortPublication(
            hostIp = port["host_ip"]?.jsonPrimitive?.contentOrNull,
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

    private fun JsonObject.requiredBoolean(name: String): Boolean =
        assertNotNull(this[name], "missing boolean: $name").jsonPrimitive.boolean

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
        val hostIp: String?,
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

    private data class ListenerFixture(
        val name: String,
        val expected: Boolean,
        val tcpRows: List<String>,
        val tcp6Rows: List<String>,
        val tcpHeader: String = PROC_NET_HEADER,
        val tcp6Header: String = DOVECOT_244_PROC_NET_TCP6_HEADER,
        val tcpFinalNewline: Boolean = true,
        val tcp6FinalNewline: Boolean = true,
    )

    private data class HealthcheckResult(
        val exitCode: Int,
        val stdout: String,
        val stderr: String,
    )

    companion object {
        private const val OPERATOR_PROFILE = "dovecot-operator"
        private const val PROVIDER_EVIDENCE_ROOT_ENV =
            "TASK5_DOVECOT_EVIDENCE_ROOT"
        private const val BASE_COMPOSE_EVIDENCE = "base-compose.json"
        private const val PROOF_COMPOSE_EVIDENCE = "proof-compose.json"
        private const val ORDINARY_DOVECONF_EVIDENCE =
            "ordinary-doveconf.txt"
        private const val OPERATOR_DOVECONF_EVIDENCE =
            "operator-doveconf.txt"
        private val PROVIDER_EVIDENCE_FILES = setOf(
            BASE_COMPOSE_EVIDENCE,
            PROOF_COMPOSE_EVIDENCE,
            ORDINARY_DOVECONF_EVIDENCE,
            OPERATOR_DOVECONF_EVIDENCE,
        )
        private const val PINNED_DOVECOT_IMAGE =
            "dovecot/dovecot:2.4.4@" +
                "sha256:723e3392fe16c6fad8ddc605ea767cc01b4bad9cd9f13eb1dbac15e79c89b2d4"
        private val OUTPUT_JOIN_TIMEOUT = Duration.ofSeconds(2)
        private const val MAX_PROVIDER_EVIDENCE_BYTES = 1024 * 1024
        private const val PROC_NET_HEADER =
            "  sl  local_address rem_address   st tx_queue rx_queue tr " +
                "tm->when retrnsmt   uid  timeout inode"
        private const val DOVECOT_244_PROC_NET_TCP6_HEADER =
            "  sl  local_address                         remote_address " +
                "                       st tx_queue rx_queue tr tm->when " +
                "retrnsmt   uid  timeout inode"
        private val EXPECTED_OPERATOR_CONFIG = """
            dovecot_config_version = 2.4.4
            dovecot_storage_version = 2.4.3

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
            auth_failure_delay = 0s

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
            mail_max_userip_connections = 16

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
                default_internal_group = vmail
                default_internal_user = vmail
                default_login_user = vmail
                listen = 127.0.0.1
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

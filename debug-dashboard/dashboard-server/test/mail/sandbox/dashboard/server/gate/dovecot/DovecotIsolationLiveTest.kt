package mail.sandbox.dashboard.server.gate.dovecot

import java.nio.file.Files
import java.nio.file.Path
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals

class DovecotIsolationLiveTest {
    @Test
    fun masterCredentialAndOperatorIngressAreIsolatedFromEveryOtherPath() {
        val repositoryRoot = repositoryRoot()
        val live = DovecotLiveTestEnvironment.load(
            environment = System.getenv(),
            repositoryRoot = repositoryRoot,
        )
        live.awaitReady()
        val launchProfile = live.operatorRuntime.launchProfile
        val eligibilityAdapter =
            Task6LaunchProfileEligibilityAdapter(launchProfile)
        val topology = FixedTask6DockerTopology(launchProfile)
        val runtime = topology.inspect()
        runtime.requireExactIsolation()

        val hostAddresses = discoverTask6HostNonLoopbackIpv4()
        hostAddresses.forEach { address ->
            requireTask6TcpRejected(address, live.ordinaryImapsPort)
            requireTask6TcpRejected(
                address,
                live.forbiddenOperatorHostPort,
            )
        }
        topology.requireDefaultNetworkIsolation(
            operatorIngressAddress = runtime.operatorIngressAddress,
            hostAddresses = hostAddresses,
        )
        val protocol = DovecotIsolationProtocolProof.pinned(
            profile = live.profile,
            operatorExchange = live.operatorExchange,
        )

        val address =
            "task6-isolation-" +
                UUID.randomUUID().toString().replace("-", "") +
                "@local.test"
        val target = DovecotOperatorTarget.create(address)
        val eligibilityPaths = live.profile.eligibilityPaths()
        val eligibilityCli = EligibilityFileCli(
            pathsProvider = { eligibilityPaths },
            hasherFactory = { eligibilityAdapter },
        )
        val store = DovecotOperatorCredentialStore(
            paths = live.profile.operatorPaths(),
            generator = DovecotOperatorSecretGenerator {
                error("isolation proof must not generate an operator secret")
            },
            hasher = DovecotOperatorHashBoundary {
                error("isolation proof must not hash an operator secret")
            },
            verifier = eligibilityAdapter,
        )
        val transportFactory = live.operatorRuntime.transportFactory()
        val probe = DovecotOperatorProbe(
            transportFactory = transportFactory,
            requireMailboxRead = true,
        )
        task6DisposableEligibilityFixture(
            address = address,
            paths = eligibilityPaths,
            executor = eligibilityCli,
            rejectionProof = {
                awaitDovecotOperatorTargetRejection(
                    resultSupplier = {
                        probe.probe(target, store.loadActive())
                    },
                )
            },
        ).run { targetPassword ->
            val activeId = store.loadActive().use { it.id }
            val leases = DovecotOperatorApplicationLeaseRegistry(activeId)
            var seedFailure: Throwable? = null
            try {
                assertEquals(
                    DovecotOperatorProbeResult.Success,
                    seedAndProbeTask6IsolationMailbox(
                        leaseRegistry = leases,
                        transportFactory = transportFactory,
                        target = target,
                        credentialSupplier = store::loadActive,
                    ),
                )
            } catch (failure: Throwable) {
                seedFailure = failure
                throw failure
            } finally {
                try {
                    leases.blockAndDrain(activeId)
                } catch (cleanupFailure: Throwable) {
                    val primary = seedFailure
                    if (primary != null) {
                        primary.addSuppressed(cleanupFailure)
                    } else {
                        throw cleanupFailure
                    }
                }
            }
            val activeMasterId = store.loadActive().use { it.id }
            protocol.requireOperatorImapRejected(
                task6MasterLogin(address, activeMasterId),
                targetPassword,
            )
            store.loadActive().use { activeCredential ->
                task6RequireInactiveMasterRejected(
                    targetAddress = address,
                    activeCredential = activeCredential,
                    requireRejected =
                        protocol::requireOperatorImapRejected,
                )
            }
            protocol.requireOperatorImapRejected(
                "$address*absent-master",
                targetPassword,
            )
            store.loadActive().use { master ->
                protocol.requireOrdinaryImapRejected(
                    task6MasterLogin(address, master.id),
                    master,
                )
                protocol.requirePop3Rejected(
                    live.ordinaryPop3sPort,
                    task6MasterLogin(address, master.id),
                    master,
                )
                protocol.requireSmtpRejected(
                    live.smtpPort,
                    task6MasterLogin(address, master.id),
                    master,
                )
                protocol.requireMasterOauthInactive(
                    live.oauthPort,
                    master,
                )
            }

            store.loadActive().use { master ->
                protocol.requireRawOperatorRejected(
                    "absent-${UUID.randomUUID()}@local.test",
                    master,
                )
            }
            PROTECTED_TARGETS.forEach { protected ->
                store.loadActive().use { master ->
                    protocol.requireRawOperatorRejected(
                        protected,
                        master,
                    )
                }
            }
            DovecotOperatorId.entries.forEach { id ->
                store.loadActive().use { master ->
                    protocol.requireRawOperatorRejected(
                        id.masterUsername,
                        master,
                    )
                }
            }
            protocol.requireProtectedOauthDenied(live.oauthPort)
        }
    }

    private fun repositoryRoot(): Path {
        val working = Path.of(System.getProperty("user.dir"))
            .toAbsolutePath()
            .normalize()
        val dashboard =
            if (working.fileName?.toString() == "dashboard-server") {
                requireNotNull(working.parent)
            } else {
                working
            }
        return requireNotNull(dashboard.parent).also {
            require(Files.isRegularFile(it.resolve("docker-compose.yml")))
        }
    }

    companion object {
        private val PROTECTED_TARGETS = listOf(
            "dashboard-management@local.test",
            "dashboard-operator-a@local.test",
            "dashboard-operator-b@local.test",
        )
    }
}

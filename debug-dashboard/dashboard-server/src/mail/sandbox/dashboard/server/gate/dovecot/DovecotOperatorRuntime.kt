package mail.sandbox.dashboard.server.gate.dovecot

import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.util.Collections

internal class DovecotOperatorRuntime private constructor(
    val launchProfile: DovecotOperatorLaunchProfile,
) {
    fun probe(
        transportFactory: DovecotOperatorTransportFactory,
    ): DovecotOperatorProbe =
        DovecotOperatorProbe(transportFactory = transportFactory)

    companion object {
        fun production(): DovecotOperatorRuntime {
            val repositoryRoot =
                DovecotOperatorPaths.production().repositoryRoot
            return production(
                repositoryRoot = repositoryRoot,
                startupEnvironment = System.getenv(),
                dockerCandidates = productionDockerCandidates,
            )
        }

        internal fun production(
            paths: DovecotOperatorPaths,
            startupEnvironment: Map<String, String>,
            dockerCandidates: List<Path>,
        ): DovecotOperatorRuntime =
            production(
                repositoryRoot = paths.repositoryRoot,
                startupEnvironment = startupEnvironment,
                dockerCandidates = dockerCandidates,
            )

        fun task5Proof(
            profile: DovecotTask5ProofProfile,
            selectedDockerCli: Path,
        ): DovecotOperatorRuntime =
            DovecotOperatorRuntime(
                DovecotOperatorLaunchProfile(
                    dockerCli = selectedDockerCli,
                    repositoryRoot = profile.repositoryRoot,
                    composeFiles = listOf(
                        profile.repositoryRoot.resolve("docker-compose.yml"),
                        profile.composeOverride,
                    ),
                    projectName = PROOF_PROJECT_NAME,
                ),
            )

        private fun production(
            repositoryRoot: Path,
            startupEnvironment: Map<String, String>,
            dockerCandidates: List<Path>,
        ): DovecotOperatorRuntime {
            val projectName = repositoryRoot.fileName?.toString()
                ?: throw IllegalArgumentException(INVALID_PROJECT_MESSAGE)
            return DovecotOperatorRuntime(
                DovecotOperatorLaunchProfile(
                    dockerCli = selectDockerCli(
                        startupEnvironment = startupEnvironment,
                        dockerCandidates = dockerCandidates,
                    ),
                    repositoryRoot = repositoryRoot,
                    composeFiles =
                        listOf(repositoryRoot.resolve("docker-compose.yml")),
                    projectName = projectName,
                ),
            )
        }

        private fun selectDockerCli(
            startupEnvironment: Map<String, String>,
            dockerCandidates: List<Path>,
        ): Path {
            val explicit = startupEnvironment[DOCKER_OVERRIDE_KEY]
            if (explicit != null) {
                val path = try {
                    Path.of(explicit)
                } catch (_: Exception) {
                    invalidDockerCli()
                }
                if (!path.isAbsolute) {
                    invalidDockerCli()
                }
                return canonicalExecutable(path) ?: invalidDockerCli()
            }

            return dockerCandidates.firstNotNullOfOrNull(
                ::canonicalExecutable,
            ) ?: throw IllegalStateException(UNAVAILABLE_DOCKER_MESSAGE)
        }

        private fun canonicalExecutable(path: Path): Path? {
            if (!path.isAbsolute) {
                return null
            }
            val canonical = try {
                path.toRealPath()
            } catch (_: Exception) {
                return null
            }
            return canonical.takeIf {
                it.isAbsolute &&
                    it.normalize() == it &&
                    Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) &&
                    !Files.isSymbolicLink(it) &&
                    Files.isExecutable(it)
            }
        }

        private fun invalidDockerCli(): Nothing =
            throw IllegalArgumentException(INVALID_DOCKER_MESSAGE)

        private const val DOCKER_OVERRIDE_KEY =
            "MAIL_SANDBOX_DOCKER_CLI"
        private const val INVALID_DOCKER_MESSAGE =
            "Dovecot operator Docker CLI is invalid"
        private const val UNAVAILABLE_DOCKER_MESSAGE =
            "Dovecot operator Docker CLI is unavailable"
        private const val INVALID_PROJECT_MESSAGE =
            "Dovecot operator Compose project is invalid"
        private const val PROOF_PROJECT_NAME =
            "mail-sandbox-task5-proof"
        internal val productionDockerCandidates: List<Path> =
            Collections.unmodifiableList(
                listOf(
                    Path.of("/usr/local/bin/docker"),
                    Path.of("/opt/homebrew/bin/docker"),
                    Path.of("/usr/bin/docker"),
                ),
            )
    }
}

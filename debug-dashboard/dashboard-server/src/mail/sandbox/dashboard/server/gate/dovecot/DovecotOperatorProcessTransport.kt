package mail.sandbox.dashboard.server.gate.dovecot

import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.util.Collections

internal class DovecotOperatorLaunchProfile(
    val dockerCli: Path,
    val repositoryRoot: Path,
    composeFiles: List<Path>,
    val projectName: String,
) {
    val composeFiles: List<Path> =
        Collections.unmodifiableList(ArrayList(composeFiles))
    val dockerHost: String = DOCKER_HOST
    val service: String = SERVICE
    val composeProfile: String = COMPOSE_PROFILE

    init {
        requireCanonicalDockerCli(dockerCli)
        requireCanonicalRepositoryRoot(repositoryRoot)
        require(this.composeFiles.isNotEmpty()) {
            "Dovecot operator Compose files are invalid"
        }
        this.composeFiles.forEach { composeFile ->
            requireCanonicalComposeFile(
                path = composeFile,
                repositoryRoot = repositoryRoot,
            )
        }
        require(PROJECT_NAME.matches(projectName)) {
            "Dovecot operator Compose project is invalid"
        }
    }

    val argv: List<String> =
        Collections.unmodifiableList(
            ArrayList(
                buildList {
                    add(dockerCli.toString())
                    add("compose")
                    add("--project-directory")
                    add(repositoryRoot.toString())
                    this@DovecotOperatorLaunchProfile
                        .composeFiles
                        .forEach { composeFile ->
                            add("-f")
                            add(composeFile.toString())
                        }
                    add("--project-name")
                    add(projectName)
                    add("--profile")
                    add(composeProfile)
                    add("exec")
                    add("-T")
                    add("--index")
                    add("1")
                    add(service)
                    add("/usr/bin/openssl")
                    add("s_client")
                    add("-quiet")
                    add("-no_ign_eof")
                    add("-nocommands")
                    add("-4")
                    add("-min_protocol")
                    add("TLSv1.2")
                    add("-max_protocol")
                    add("TLSv1.3")
                    add("-verify_return_error")
                    add("-verify_hostname")
                    add("localhost")
                    add("-no-CApath")
                    add("-no-CAstore")
                    add("-CAfile")
                    add("/etc/dovecot/ssl/tls.crt")
                    add("-connect")
                    add("127.0.0.1:31993")
                    add("-servername")
                    add("localhost")
                },
            ),
        )

    fun sanitizedEnvironment(
        inheritedEnvironment: Map<String, String>,
    ): Map<String, String> {
        val sanitized = LinkedHashMap<String, String>()
        inheritedEnvironment.forEach { (key, value) ->
            if (CONTROL_PREFIXES.none(key::startsWith)) {
                sanitized[key] = value
            }
        }
        sanitized["COMPOSE_DISABLE_ENV_FILE"] = "1"
        sanitized["DOCKER_HOST"] = dockerHost
        return Collections.unmodifiableMap(sanitized)
    }

    internal companion object {
        const val DOCKER_HOST = "unix:///var/run/docker.sock"
        const val SERVICE = "dovecot-operator"
        const val COMPOSE_PROFILE = "dovecot-operator"

        private val PROJECT_NAME = Regex("[a-z0-9][a-z0-9_-]*")
        private val CONTROL_PREFIXES =
            listOf("COMPOSE_", "DOCKER_", "DOVECOT_")
    }
}

internal fun interface DovecotOperatorProcessStarter {
    fun start(profile: DovecotOperatorLaunchProfile): Process
}

internal class JvmDovecotOperatorProcessStarter(
    private val inheritedEnvironment: () -> Map<String, String> = {
        System.getenv()
    },
    private val builderLauncher: (ProcessBuilder) -> Process = { builder ->
        builder.start()
    },
) : DovecotOperatorProcessStarter {
    override fun start(profile: DovecotOperatorLaunchProfile): Process {
        val builder =
            ProcessBuilder(profile.argv)
                .directory(profile.repositoryRoot.toFile())
                .redirectError(ProcessBuilder.Redirect.DISCARD)
        builder.environment().apply {
            clear()
            putAll(profile.sanitizedEnvironment(inheritedEnvironment()))
        }
        return builderLauncher(builder)
    }
}

private fun requireCanonicalDockerCli(path: Path) {
    require(
        path.isAbsolute &&
            path.normalize() == path &&
            Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) &&
            !Files.isSymbolicLink(path) &&
            Files.isExecutable(path) &&
            path.isCanonical(),
    ) {
        "Dovecot operator Docker CLI is invalid"
    }
}

private fun requireCanonicalRepositoryRoot(path: Path) {
    require(
        path.isAbsolute &&
            path.normalize() == path &&
            Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) &&
            !Files.isSymbolicLink(path) &&
            path.isCanonical(),
    ) {
        "Dovecot operator repository root is invalid"
    }
}

private fun requireCanonicalComposeFile(
    path: Path,
    repositoryRoot: Path,
) {
    require(
        path.isAbsolute &&
            path.normalize() == path &&
            path.startsWith(repositoryRoot) &&
            Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) &&
            !Files.isSymbolicLink(path) &&
            path.isCanonical(),
    ) {
        "Dovecot operator Compose files are invalid"
    }
}

private fun Path.isCanonical(): Boolean =
    runCatching { toRealPath() == this }.getOrDefault(false)

package mail.sandbox.dashboard.server.gate.dovecot

import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import java.nio.file.attribute.UserPrincipal

internal class DovecotTask5ProofProfile private constructor(
    val repositoryRoot: Path,
    val runtimeRoot: Path,
    val tlsCertificate: Path,
    val tlsPrivateKey: Path,
    val composeOverride: Path,
    val loopbackAddress: String,
    val ordinaryImapsPort: Int,
    val ordinaryPop3sPort: Int,
    val forbiddenOperatorHostPort: Int,
    val smtpPort: Int,
    val oauthPort: Int,
    internal val dockerRoutingEnvironment: Map<String, String>,
    private val trustedOwner: UserPrincipal,
) {
    @Deprecated(
        message = "Task 5 removes this compatibility alias.",
        replaceWith = ReplaceWith("forbiddenOperatorHostPort"),
    )
    internal val operatorImapsPort: Int
        get() = forbiddenOperatorHostPort

    fun eligibilityPaths(): EligibilityPaths =
        EligibilityPaths.task5Proof(repositoryRoot)

    fun operatorPaths(): DovecotOperatorPaths =
        DovecotOperatorPaths.task5Proof(repositoryRoot)

    fun readStableTlsCertificate(): ByteArray {
        requirePreparedTls()
        val before = Files.readAttributes(
            tlsCertificate,
            BasicFileAttributes::class.java,
            LinkOption.NOFOLLOW_LINKS,
        )
        require(before.size() in 1..MAX_CERTIFICATE_BYTES) {
            "Dovecot proof certificate size is invalid"
        }
        val bytes = Files.newInputStream(
            tlsCertificate,
            LinkOption.NOFOLLOW_LINKS,
        ).use { input ->
            input.readNBytes(MAX_CERTIFICATE_BYTES + 1)
        }
        try {
            require(bytes.size.toLong() == before.size()) {
                "Dovecot proof certificate changed while being read"
            }
            val after = Files.readAttributes(
                tlsCertificate,
                BasicFileAttributes::class.java,
                LinkOption.NOFOLLOW_LINKS,
            )
            require(
                after.isRegularFile &&
                    before.fileKey() == after.fileKey() &&
                    before.size() == after.size() &&
                    before.lastModifiedTime() == after.lastModifiedTime(),
            ) {
                "Dovecot proof certificate changed while being read"
            }
            requirePreparedTls()
            return bytes
        } catch (failure: Throwable) {
            bytes.fill(0)
            throw failure
        }
    }

    fun requirePreparedTls() {
        requireProofRuntimeDirectory(
            repositoryRoot.resolve("debug-dashboard/.runtime"),
            exactOwnerOnly = false,
        )
        requireProofRuntimeDirectory(runtimeRoot, exactOwnerOnly = true)
        requireProofRuntimeDirectory(
            runtimeRoot.resolve("ssl"),
            exactOwnerOnly = true,
        )
        requireProofFile(tlsCertificate)
        requireProofFile(tlsPrivateKey)
    }

    private fun requireProofRuntimeDirectory(
        path: Path,
        exactOwnerOnly: Boolean,
    ) {
        require(
            path.isAbsolute &&
                path.normalize() == path &&
                Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(path) &&
                path.toRealPath() == path &&
                Files.getOwner(path, LinkOption.NOFOLLOW_LINKS) ==
                trustedOwner &&
                path.fileSystem.supportedFileAttributeViews()
                    .contains("posix"),
        ) {
            "Dovecot proof TLS directory is unsafe"
        }
        val permissions = Files.getPosixFilePermissions(
            path,
            LinkOption.NOFOLLOW_LINKS,
        )
        require(
            if (exactOwnerOnly) {
                permissions == OWNER_ONLY_DIRECTORY_PERMISSIONS
            } else {
                PosixFilePermission.OWNER_READ in permissions &&
                    PosixFilePermission.OWNER_WRITE in permissions &&
                    PosixFilePermission.OWNER_EXECUTE in permissions &&
                    PosixFilePermission.GROUP_WRITE !in permissions &&
                    PosixFilePermission.OTHERS_WRITE !in permissions
            },
        ) {
            "Dovecot proof TLS directory permissions are unsafe"
        }
    }

    private fun requireProofFile(path: Path) {
        require(
            path.isAbsolute &&
                path.normalize() == path &&
                Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(path) &&
                path.toRealPath() == path &&
                Files.getOwner(path, LinkOption.NOFOLLOW_LINKS) ==
                trustedOwner &&
                path.fileSystem.supportedFileAttributeViews()
                    .contains("posix") &&
                Files.getPosixFilePermissions(
                    path,
                    LinkOption.NOFOLLOW_LINKS,
                ) == OWNER_ONLY_FILE_PERMISSIONS &&
                singleLinkCount(path),
        ) {
            "Dovecot proof TLS file is unsafe"
        }
        val productionPeer = repositoryRoot.resolve(
            "ssl/${path.fileName}",
        )
        require(
            Files.notExists(productionPeer, LinkOption.NOFOLLOW_LINKS) ||
                !Files.isSameFile(path, productionPeer),
        ) {
            "Dovecot proof TLS file aliases production TLS"
        }
    }

    private fun singleLinkCount(path: Path): Boolean =
        runCatching {
            val count = Files.getAttribute(
                path,
                "unix:nlink",
                LinkOption.NOFOLLOW_LINKS,
            ) as Number
            count.toLong() == 1L
        }.getOrDefault(false)

    override fun toString(): String =
        "DovecotTask5ProofProfile(fixed, paths=redacted)"

    companion object {
        private const val LIVE_TESTS_KEY = "DOVECOT_LIVE_TESTS"
        private const val LIVE_PROFILE_KEY = "DOVECOT_LIVE_PROFILE"
        private const val COMPOSE_PROJECT_KEY = "COMPOSE_PROJECT_NAME"
        private const val COMPOSE_FILE_KEY = "COMPOSE_FILE"
        private const val COMPOSE_DISABLE_ENV_FILE_KEY =
            "COMPOSE_DISABLE_ENV_FILE"
        private const val DOCKER_HOST_KEY = "DOCKER_HOST"
        private const val FIXED_DOCKER_HOST =
            "unix:///var/run/docker.sock"
        private const val FIXED_PROFILE = "task5-proof"
        private const val FIXED_PROJECT = "mail-sandbox-task5-proof"
        private const val FIXED_LOOPBACK = "127.0.0.1"
        private const val ORDINARY_IMAPS_PORT = 1993
        private const val ORDINARY_POP3S_PORT = 21995
        private const val FORBIDDEN_OPERATOR_HOST_PORT = 2993
        private const val SMTP_PORT = 21025
        private const val OAUTH_PORT = 28080
        private const val OVERRIDE_RELATIVE_PATH =
            "debug-dashboard/dashboard-server/testResources/" +
                "dovecot-gate0c/compose.task5-proof.yml"
        private val FIXED_COMPOSE_FILES =
            "docker-compose.yml" + File.pathSeparator + OVERRIDE_RELATIVE_PATH
        private val ALLOWED_DOVECOT_KEYS = setOf(
            LIVE_TESTS_KEY,
            LIVE_PROFILE_KEY,
        )
        private val ALLOWED_COMPOSE_KEYS = setOf(
            COMPOSE_PROJECT_KEY,
            COMPOSE_FILE_KEY,
            COMPOSE_DISABLE_ENV_FILE_KEY,
        )

        fun load(
            environment: Map<String, String> = System.getenv(),
            repositoryRoot: Path,
        ): DovecotTask5ProofProfile {
            require(environment[LIVE_TESTS_KEY] == "1") {
                "$LIVE_TESTS_KEY=1 is required for the selected live proof"
            }
            require(environment[LIVE_PROFILE_KEY] == FIXED_PROFILE) {
                "$LIVE_PROFILE_KEY=$FIXED_PROFILE is required"
            }
            require(environment[COMPOSE_PROJECT_KEY] == FIXED_PROJECT) {
                "$COMPOSE_PROJECT_KEY must select the fixed proof project"
            }
            require(environment[COMPOSE_FILE_KEY] == FIXED_COMPOSE_FILES) {
                "$COMPOSE_FILE_KEY must select the fixed proof Compose files"
            }
            require(environment[COMPOSE_DISABLE_ENV_FILE_KEY] == "1") {
                "$COMPOSE_DISABLE_ENV_FILE_KEY=1 is required"
            }
            require(environment[DOCKER_HOST_KEY] == FIXED_DOCKER_HOST) {
                "$DOCKER_HOST_KEY must select the fixed local Docker daemon"
            }
            require(
                environment.keys
                    .filter { it.startsWith("DOVECOT_") }
                    .all { it in ALLOWED_DOVECOT_KEYS },
            ) {
                "Arbitrary Dovecot live settings are forbidden"
            }
            require(
                environment.keys
                    .filter { it.startsWith("COMPOSE_") }
                    .all { it in ALLOWED_COMPOSE_KEYS },
            ) {
                "Arbitrary Compose settings are forbidden for the fixed proof"
            }
            require(
                environment.keys
                    .filter { it.startsWith("DOCKER_") }
                    .all { it == DOCKER_HOST_KEY },
            ) {
                "Arbitrary Docker routing settings are forbidden for the fixed proof"
            }

            val root = repositoryRoot.toAbsolutePath().normalize()
            require(
                root == repositoryRoot &&
                    Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS) &&
                    !Files.isSymbolicLink(root) &&
                    root.toRealPath() == root,
            ) {
                "Dovecot proof repository root is invalid"
            }
            requireFixedFile(root.resolve("docker-compose.yml"))
            requireFixedFile(root.resolve("debug-dashboard/project.yaml"))
            val override = root.resolve(OVERRIDE_RELATIVE_PATH)
            requireFixedFile(override)
            val runtimeRoot = root.resolve(
                "debug-dashboard/.runtime/task5-proof",
            )
            val trustedOwner = Files.getOwner(
                root,
                LinkOption.NOFOLLOW_LINKS,
            )
            require(
                Files.getOwner(
                    root.resolve("debug-dashboard"),
                    LinkOption.NOFOLLOW_LINKS,
                ) == trustedOwner,
            ) {
                "Dovecot proof repository ownership is inconsistent"
            }

            return DovecotTask5ProofProfile(
                repositoryRoot = root,
                runtimeRoot = runtimeRoot,
                tlsCertificate = runtimeRoot.resolve("ssl/tls.crt"),
                tlsPrivateKey = runtimeRoot.resolve("ssl/tls.key"),
                composeOverride = override,
                loopbackAddress = FIXED_LOOPBACK,
                ordinaryImapsPort = ORDINARY_IMAPS_PORT,
                ordinaryPop3sPort = ORDINARY_POP3S_PORT,
                forbiddenOperatorHostPort = FORBIDDEN_OPERATOR_HOST_PORT,
                smtpPort = SMTP_PORT,
                oauthPort = OAUTH_PORT,
                dockerRoutingEnvironment = mapOf(
                    DOCKER_HOST_KEY to FIXED_DOCKER_HOST,
                    COMPOSE_PROJECT_KEY to FIXED_PROJECT,
                    COMPOSE_FILE_KEY to FIXED_COMPOSE_FILES,
                    COMPOSE_DISABLE_ENV_FILE_KEY to "1",
                ),
                trustedOwner = trustedOwner,
            )
        }

        private fun requireFixedFile(path: Path) {
            require(
                path.isAbsolute &&
                    path.normalize() == path &&
                    Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) &&
                    !Files.isSymbolicLink(path) &&
                    path.toRealPath(LinkOption.NOFOLLOW_LINKS) == path,
            ) {
                "Dovecot proof file layout is invalid"
            }
        }

        private const val MAX_CERTIFICATE_BYTES = 64 * 1024
        private val OWNER_ONLY_DIRECTORY_PERMISSIONS =
            PosixFilePermissions.fromString("rwx------")
        private val OWNER_ONLY_FILE_PERMISSIONS =
            PosixFilePermissions.fromString("rw-------")
    }
}

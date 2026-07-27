package mail.sandbox.dashboard.server.gate.stalwart

import java.nio.file.FileVisitResult
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.SimpleFileVisitor
import java.nio.file.attribute.BasicFileAttributes
import java.security.MessageDigest

internal data class StalwartReviewedFileState(
    val path: Path,
    val fileKey: String,
    val size: Long,
    val lastModifiedMillis: Long,
    val sha256: String,
)

internal data class StalwartReviewedDirectoryState(
    val path: Path,
    val fileKey: String,
)

internal data class StalwartHostOwner(
    val uid: Int,
    val gid: Int,
)

internal data class StalwartGateCleanupPlan(
    val projectRoot: Path,
    val projectName: String,
    val runtimeDirectory: Path,
    val baseComposeFile: Path,
    val configFile: Path,
    val dataDirectory: Path,
    val baseComposeState: StalwartReviewedFileState,
    val configState: StalwartReviewedFileState,
    val dataDirectoryState: StalwartReviewedDirectoryState,
    val hostOwner: StalwartHostOwner,
    val composeStopCommand: List<String>,
    val dataReleaseCommand: List<String>,
    val composeDownCommand: List<String>,
)

internal object StalwartGateCleanup {
    private const val PROJECT_NAME = "mail-sandbox-stalwart-gate"
    private const val BASE_COMPOSE_RELATIVE =
        "dashboard-server/testResources/stalwart-gate0b/compose.yml"
    private const val CONFIG_RELATIVE =
        "dashboard-server/testResources/stalwart-gate0b/config.json"

    fun plan(
        projectRoot: Path,
        requestedProjectName: String,
        requestedRuntimeDirectory: Path,
    ): StalwartGateCleanupPlan {
        require(requestedProjectName == PROJECT_NAME) {
            "Cleanup is restricted to the named Stalwart gate project"
        }
        val root = projectRoot.toAbsolutePath().normalize()
        require(
            Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(root),
        ) {
            "Cleanup project root is absent or symbolic"
        }
        val canonicalRoot = root.toRealPath()
        requireRegularFile(canonicalRoot.resolve("project.yaml"), "project marker")
        val ignoreFile = canonicalRoot.resolve(".gitignore")
        requireRegularFile(ignoreFile, "project ignore file")
        require(Files.readAllLines(ignoreFile).any { it.trim() == "/.runtime/" }) {
            "Gate runtime is not covered by the dashboard project ignore rule"
        }

        val runtimeParent = canonicalRoot.resolve(".runtime")
        require(
            Files.isDirectory(runtimeParent, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(runtimeParent),
        ) {
            "Gate runtime parent is absent or symbolic"
        }
        val expectedRuntime = runtimeParent.toRealPath().resolve("stalwart-gate0b")
        val requested = requestedRuntimeDirectory.toAbsolutePath().normalize()
        require(
            requested.fileName?.toString() == "stalwart-gate0b" &&
                Files.isDirectory(requested.parent, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(requested.parent) &&
                requested.parent.toRealPath() == runtimeParent.toRealPath(),
        ) {
            "Cleanup target is not the exact gate-owned runtime"
        }
        val canonicalRuntime = if (Files.exists(requested, LinkOption.NOFOLLOW_LINKS)) {
            require(
                Files.isDirectory(requested, LinkOption.NOFOLLOW_LINKS) &&
                    !Files.isSymbolicLink(requested),
            ) {
                "Cleanup target is not a real directory"
            }
            requested.toRealPath()
        } else {
            expectedRuntime
        }
        require(canonicalRuntime == expectedRuntime && canonicalRuntime != canonicalRoot) {
            "Cleanup target escaped the exact gate-owned runtime"
        }

        val baseCompose = canonicalRoot.resolve(BASE_COMPOSE_RELATIVE)
        val config = canonicalRoot.resolve(CONFIG_RELATIVE)
        val reviewedCompose = readReviewedFile(baseCompose, "gate Compose file")
        val reviewedConfig = readReviewedFile(config, "gate config file")
        StalwartFixtureAudit.validateBase(
            baseCompose = reviewedCompose.bytes.toString(Charsets.UTF_8),
            configJson = reviewedConfig.bytes.toString(Charsets.UTF_8),
        )
        val dataState = readReviewedDirectory(
            canonicalRuntime.resolve("data"),
            "gate data directory",
        )
        val hostOwner = readHostOwner(canonicalRuntime)
        val canonicalCompose = reviewedCompose.state.path
        val composePrefix = listOf(
            "docker",
            "compose",
            "-p",
            PROJECT_NAME,
            "-f",
            canonicalCompose.toString(),
        )
        val stopCommand = composePrefix + listOf("stop", "stalwart")
        val dataReleaseCommand = composePrefix + listOf(
            "run",
            "--rm",
            "--no-deps",
            "--user",
            "0:0",
            "--entrypoint",
            "/bin/sh",
            "stalwart-data-owner",
            "-c",
            "chown -R ${hostOwner.uid}:${hostOwner.gid} /var/lib/stalwart && " +
                "chmod -R u+rwX,go-rwx /var/lib/stalwart",
        )
        val downCommand = composePrefix + listOf(
            "down",
        )
        require(
            (stopCommand + dataReleaseCommand + downCommand).none {
                it == "-v" || it == "--volumes"
            },
        ) {
            "Gate cleanup must never delete Docker volumes"
        }
        return StalwartGateCleanupPlan(
            projectRoot = canonicalRoot,
            projectName = PROJECT_NAME,
            runtimeDirectory = canonicalRuntime,
            baseComposeFile = canonicalCompose,
            configFile = reviewedConfig.state.path,
            dataDirectory = dataState.path,
            baseComposeState = reviewedCompose.state,
            configState = reviewedConfig.state,
            dataDirectoryState = dataState,
            hostOwner = hostOwner,
            composeStopCommand = stopCommand,
            dataReleaseCommand = dataReleaseCommand,
            composeDownCommand = downCommand,
        )
    }

    fun cleanup(
        plan: StalwartGateCleanupPlan,
        commandRunner: (List<String>) -> Int,
    ) {
        listOf(
            plan.composeStopCommand to "stop",
            plan.dataReleaseCommand to "data release",
            plan.composeDownCommand to "down",
        ).forEach { (command, label) ->
            revalidate(plan)
            check(commandRunner(command) == 0) {
                "Named Stalwart gate project $label command failed"
            }
        }
        revalidate(plan)

        val target = plan.runtimeDirectory
        if (!Files.exists(target, LinkOption.NOFOLLOW_LINKS)) return

        Files.walkFileTree(
            target,
            object : SimpleFileVisitor<Path>() {
                override fun preVisitDirectory(
                    directory: Path,
                    attributes: BasicFileAttributes,
                ): FileVisitResult {
                    require(!Files.isSymbolicLink(directory) && attributes.isDirectory) {
                        "Cleanup encountered a symbolic or non-directory path"
                    }
                    require(directory.toRealPath().startsWith(target)) {
                        "Cleanup directory escaped the exact gate runtime"
                    }
                    return FileVisitResult.CONTINUE
                }

                override fun visitFile(
                    file: Path,
                    attributes: BasicFileAttributes,
                ): FileVisitResult {
                    require(!Files.isSymbolicLink(file) && attributes.isRegularFile) {
                        "Cleanup encountered a symbolic or non-regular file"
                    }
                    require(file.parent.toRealPath().startsWith(target)) {
                        "Cleanup file escaped the exact gate runtime"
                    }
                    Files.delete(file)
                    return FileVisitResult.CONTINUE
                }

                override fun postVisitDirectory(
                    directory: Path,
                    failure: java.io.IOException?,
                ): FileVisitResult {
                    if (failure != null) throw failure
                    Files.delete(directory)
                    return FileVisitResult.CONTINUE
                }
            },
        )
        require(!Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
            "Gate runtime cleanup did not remove the exact target"
        }
    }

    private fun requireRegularFile(path: Path, label: String) {
        require(
            Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(path),
        ) {
            "$label is absent or symbolic"
        }
    }

    private fun revalidate(expected: StalwartGateCleanupPlan) {
        val actual = plan(
            projectRoot = expected.projectRoot,
            requestedProjectName = expected.projectName,
            requestedRuntimeDirectory = expected.runtimeDirectory,
        )
        require(actual == expected) {
            "Cleanup fixture or gate data identity changed after review"
        }
    }

    private fun readReviewedFile(path: Path, label: String): ReviewedFile {
        val normalized = path.toAbsolutePath().normalize()
        requireRegularFile(normalized, label)
        require(normalized.toRealPath() == normalized) {
            "$label escaped through a symbolic path"
        }
        val before = Files.readAttributes(
            normalized,
            BasicFileAttributes::class.java,
            LinkOption.NOFOLLOW_LINKS,
        )
        val bytes = Files.readAllBytes(normalized)
        val after = Files.readAttributes(
            normalized,
            BasicFileAttributes::class.java,
            LinkOption.NOFOLLOW_LINKS,
        )
        require(
            before.fileKey() != null &&
                before.fileKey() == after.fileKey() &&
                before.size() == after.size() &&
                before.lastModifiedTime() == after.lastModifiedTime(),
        ) {
            "$label changed while it was being reviewed"
        }
        return ReviewedFile(
            bytes = bytes,
            state = StalwartReviewedFileState(
                path = normalized,
                fileKey = before.fileKey().toString(),
                size = before.size(),
                lastModifiedMillis = before.lastModifiedTime().toMillis(),
                sha256 = sha256(bytes),
            ),
        )
    }

    private fun readReviewedDirectory(
        path: Path,
        label: String,
    ): StalwartReviewedDirectoryState {
        val normalized = path.toAbsolutePath().normalize()
        require(
            Files.isDirectory(normalized, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(normalized) &&
                normalized.toRealPath() == normalized,
        ) {
            "$label is absent, symbolic, or outside the reviewed path"
        }
        val attributes = Files.readAttributes(
            normalized,
            BasicFileAttributes::class.java,
            LinkOption.NOFOLLOW_LINKS,
        )
        require(attributes.fileKey() != null) {
            "$label does not expose a stable filesystem identity"
        }
        return StalwartReviewedDirectoryState(
            path = normalized,
            fileKey = attributes.fileKey().toString(),
        )
    }

    private fun readHostOwner(runtimeDirectory: Path): StalwartHostOwner {
        val attributes = Files.readAttributes(
            runtimeDirectory,
            "unix:uid,gid,mode",
            LinkOption.NOFOLLOW_LINKS,
        )
        val mode = (attributes["mode"] as? Number)?.toInt()
            ?: throw IllegalArgumentException(
                "Gate runtime has no numeric Unix mode",
            )
        require(mode and 0x1ff == 0x1c0) {
            "Gate runtime must remain owner-only"
        }

        fun readId(attribute: String): Int {
            val value = (attributes[attribute] as? Number)?.toLong()
                ?: throw IllegalArgumentException(
                    "Gate runtime has no numeric Unix $attribute",
                )
            require(value in 0..Int.MAX_VALUE.toLong()) {
                "Gate runtime Unix $attribute is outside the reviewed range"
            }
            return value.toInt()
        }
        return StalwartHostOwner(
            uid = readId("uid"),
            gid = readId("gid"),
        )
    }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256")
            .digest(bytes)
            .joinToString(separator = "") { byte -> "%02x".format(byte) }

    private data class ReviewedFile(
        val bytes: ByteArray,
        val state: StalwartReviewedFileState,
    )
}

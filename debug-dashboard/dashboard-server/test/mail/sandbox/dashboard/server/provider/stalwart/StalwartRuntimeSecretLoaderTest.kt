package mail.sandbox.dashboard.server.provider.stalwart

import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class StalwartRuntimeSecretLoaderTest {
    @Test
    fun productionPathsAreFixedAndLoadOwnerOnlyRuntimeMaterial() {
        withProject { projectRoot ->
            val paths = StalwartRuntimeSecretPaths.production(projectRoot)
            val canonicalRoot = projectRoot.toRealPath()
            assertEquals(
                canonicalRoot.resolve(".runtime/secrets/stalwart-management-api-key"),
                paths.managementApiKey,
            )
            assertEquals(
                canonicalRoot.resolve(".runtime/stalwart/protected-accounts.json"),
                paths.protectedAccounts,
            )

            val canary = managementApiKey('A')
            writeRuntimeMaterial(
                paths = paths,
                managementApiKey = canary,
                protectedAccountIds = listOf("management-account-id"),
            )

            StalwartRuntimeSecretLoader(paths).load().use { loaded ->
                assertEquals(
                    setOf("management-account-id"),
                    loaded.protectedAccountIds,
                )
                var callbackBytes: ByteArray? = null
                loaded.withManagementApiKey { borrowed ->
                    callbackBytes = borrowed
                    assertContentEquals(canary, borrowed)
                }
                assertTrue(callbackBytes!!.all { it == 0.toByte() })
                assertFalse(loaded.toString().contains(canary.decodeToString()))
                assertFalse(paths.toString().contains(paths.managementApiKey.toString()))
            }
        }
    }

    @Test
    fun closingLoadedMaterialDisablesFurtherSecretAccessAndKeepsDiagnosticsRedacted() {
        withProject { projectRoot ->
            val paths = StalwartRuntimeSecretPaths.production(projectRoot)
            val canary = managementApiKey('B')
            writeRuntimeMaterial(
                paths = paths,
                managementApiKey = canary,
                protectedAccountIds = listOf("management-account-id"),
            )
            val loaded = StalwartRuntimeSecretLoader(paths).load()

            loaded.close()
            val failure = assertFailsWith<IllegalStateException> {
                loaded.withManagementApiKey { error("must not run") }
            }

            assertFalse(failure.toString().contains(canary.decodeToString()))
            assertFalse(loaded.toString().contains(canary.decodeToString()))
        }
    }

    @Test
    fun strictProtectedAccountDocumentRejectsDuplicatesExtrasAndNonCanonicalIds() {
        val malformedDocuments = listOf(
            """{"account_ids":["management-account-id"],"schema":"wrong"}""",
            """{"account_ids":[],"schema":"$PROTECTED_ACCOUNTS_SCHEMA"}""",
            """{"account_ids":["first","second"],"schema":"$PROTECTED_ACCOUNTS_SCHEMA"}""",
            """{"account_ids":["duplicate","duplicate"],"schema":"$PROTECTED_ACCOUNTS_SCHEMA"}""",
            """{"account_ids":["../escape"],"schema":"$PROTECTED_ACCOUNTS_SCHEMA"}""",
            """{"account_ids":[1],"schema":"$PROTECTED_ACCOUNTS_SCHEMA"}""",
            """{"account_ids":["valid"],"extra":true,"schema":"$PROTECTED_ACCOUNTS_SCHEMA"}""",
            """{"account_ids":["first"],"account_ids":["second"],"schema":"$PROTECTED_ACCOUNTS_SCHEMA"}""",
            """{"schema":"$PROTECTED_ACCOUNTS_SCHEMA","account_ids":["valid"]}""",
        )

        malformedDocuments.forEach { document ->
            withProject { projectRoot ->
                val paths = StalwartRuntimeSecretPaths.production(projectRoot)
                writeRuntimeMaterial(
                    paths = paths,
                    managementApiKey = managementApiKey('C'),
                    protectedAccountIds = listOf("placeholder"),
                )
                writeOwnerOnly(
                    paths.protectedAccounts,
                    document.encodeToByteArray() + byteArrayOf('\n'.code.toByte()),
                )

                assertFailsWith<IllegalArgumentException>(document) {
                    StalwartRuntimeSecretLoader(paths).load()
                }
            }
        }
    }

    @Test
    fun managementKeyRejectsNewlinesNulsWrongPrefixAndOversizeWithoutEchoingValues() {
        val malformedSecrets = listOf(
            byteArrayOf(),
            "not-an-api-key".encodeToByteArray(),
            "API_line\nbreak".encodeToByteArray(),
            "API_carriage\rreturn".encodeToByteArray(),
            "API_nul\u0000byte".encodeToByteArray(),
            "API_short".encodeToByteArray(),
            ("API_" + "!".repeat(38)).encodeToByteArray(),
            ("API_" + "A".repeat(37)).encodeToByteArray(),
            ("API_" + "A".repeat(39)).encodeToByteArray(),
            byteArrayOf(0x41, 0x50, 0x49, 0x5f, 0x80.toByte()),
            ByteArray(MAX_MANAGEMENT_API_KEY_BYTES + 1) { 'A'.code.toByte() }
                .also {
                    "API_".encodeToByteArray().copyInto(it)
                },
        )

        malformedSecrets.forEach { malformed ->
            withProject { projectRoot ->
                val paths = StalwartRuntimeSecretPaths.production(projectRoot)
                writeRuntimeMaterial(
                    paths = paths,
                    managementApiKey = managementApiKey('C'),
                    protectedAccountIds = listOf("management-account-id"),
                )
                writeOwnerOnly(paths.managementApiKey, malformed)

                val failure = assertFailsWith<IllegalArgumentException> {
                    StalwartRuntimeSecretLoader(paths).load()
                }
                val diagnostic = failure.toString()
                if (malformed.size in 1..256) {
                    assertFalse(diagnostic.contains(malformed.decodeToString()))
                }
            }
        }
    }

    @Test
    fun everyLoadRejectsPermissiveNonRegularOrSymbolicRuntimeInputs() {
        withProject { projectRoot ->
            val paths = StalwartRuntimeSecretPaths.production(projectRoot)
            writeRuntimeMaterial(
                paths = paths,
                managementApiKey = managementApiKey('C'),
                protectedAccountIds = listOf("management-account-id"),
            )

            if (supportsPosix(paths.managementApiKey)) {
                Files.setPosixFilePermissions(
                    paths.managementApiKey,
                    PosixFilePermissions.fromString("rw-r--r--"),
                )
                assertFailsWith<IllegalArgumentException> {
                    StalwartRuntimeSecretLoader(paths).load()
                }
                setOwnerOnlyFile(paths.managementApiKey)
            }

            Files.delete(paths.protectedAccounts)
            Files.createDirectory(paths.protectedAccounts)
            setOwnerOnlyDirectory(paths.protectedAccounts)
            assertFailsWith<IllegalArgumentException> {
                StalwartRuntimeSecretLoader(paths).load()
            }

            Files.delete(paths.protectedAccounts)
            val outside = projectRoot.resolve("outside-protected.json")
            writeOwnerOnly(
                outside,
                protectedAccountsBytes(listOf("management-account-id")),
            )
            Files.createSymbolicLink(paths.protectedAccounts, outside)
            assertFailsWith<IllegalArgumentException> {
                StalwartRuntimeSecretLoader(paths).load()
            }
        }
    }

    @Test
    fun pathsAndAncestorsAreRevalidatedAfterConfiguration() {
        withProject { projectRoot ->
            val paths = StalwartRuntimeSecretPaths.production(projectRoot)
            writeRuntimeMaterial(
                paths = paths,
                managementApiKey = managementApiKey('C'),
                protectedAccountIds = listOf("management-account-id"),
            )

            val secretsDirectory = paths.managementApiKey.parent
            Files.delete(paths.managementApiKey)
            Files.delete(secretsDirectory)
            val outside = projectRoot.resolve("outside-secrets")
            Files.createDirectory(outside)
            setOwnerOnlyDirectory(outside)
            writeOwnerOnly(
                outside.resolve(paths.managementApiKey.fileName),
                managementApiKey('D'),
            )
            Files.createSymbolicLink(secretsDirectory, outside)

            assertFailsWith<IllegalArgumentException> {
                StalwartRuntimeSecretLoader(paths).load()
            }
        }
    }

    @Test
    fun rejectsEitherRuntimeFileChangingAcrossTheCombinedLoad() {
        StalwartRuntimeSecretLoadPoint.entries.forEach { mutationPoint ->
            withProject { projectRoot ->
                val paths = StalwartRuntimeSecretPaths.production(projectRoot)
                writeRuntimeMaterial(
                    paths = paths,
                    managementApiKey = managementApiKey('E'),
                    protectedAccountIds = listOf("management-account-id"),
                )
                val loader = StalwartRuntimeSecretLoader(paths) { observedPoint ->
                    if (observedPoint != mutationPoint) return@StalwartRuntimeSecretLoader
                    when (observedPoint) {
                        StalwartRuntimeSecretLoadPoint.AfterManagementKeyRead -> {
                            replaceOwnerOnly(
                                paths.managementApiKey,
                                managementApiKey('F'),
                            )
                        }

                        StalwartRuntimeSecretLoadPoint.AfterProtectedAccountsRead -> {
                            replaceOwnerOnly(
                                paths.protectedAccounts,
                                protectedAccountsBytes(listOf("replacement-account-id")),
                            )
                        }
                    }
                }

                assertFailsWith<IllegalArgumentException>(mutationPoint.name) {
                    loader.load()
                }
            }
        }
    }

    @Test
    fun productionConfigurationRejectsMissingMarkersAndSymbolicProjectRoots() {
        withRoot { root ->
            assertFailsWith<IllegalArgumentException> {
                StalwartRuntimeSecretPaths.production(root)
            }

            Files.writeString(root.resolve("project.yaml"), "modules: []\n")
            val linkedRoot = root.resolveSibling("${root.fileName}-link")
            Files.createSymbolicLink(linkedRoot, root)
            try {
                assertFailsWith<IllegalArgumentException> {
                    StalwartRuntimeSecretPaths.production(linkedRoot)
                }
            } finally {
                Files.deleteIfExists(linkedRoot)
            }
        }
    }

    private fun writeRuntimeMaterial(
        paths: StalwartRuntimeSecretPaths,
        managementApiKey: ByteArray,
        protectedAccountIds: List<String>,
    ) {
        val runtime = paths.managementApiKey.parent.parent
        Files.createDirectory(runtime)
        setOwnerOnlyDirectory(runtime)
        Files.createDirectory(paths.managementApiKey.parent)
        setOwnerOnlyDirectory(paths.managementApiKey.parent)
        Files.createDirectory(paths.protectedAccounts.parent)
        setOwnerOnlyDirectory(paths.protectedAccounts.parent)
        writeOwnerOnly(paths.managementApiKey, managementApiKey)
        writeOwnerOnly(
            paths.protectedAccounts,
            protectedAccountsBytes(protectedAccountIds),
        )
    }

    private fun managementApiKey(fill: Char): ByteArray =
        ("API_" + fill.toString().repeat(38)).encodeToByteArray()

    private fun protectedAccountsBytes(accountIds: List<String>): ByteArray =
        buildString {
            append("{\"account_ids\":[\"")
            append(accountIds.joinToString("\",\""))
            append("\"],\"schema\":\"$PROTECTED_ACCOUNTS_SCHEMA\"}\n")
        }.encodeToByteArray()

    private fun writeOwnerOnly(path: Path, bytes: ByteArray) {
        Files.write(path, bytes)
        setOwnerOnlyFile(path)
    }

    private fun replaceOwnerOnly(path: Path, bytes: ByteArray) {
        val replacement = path.resolveSibling(".${path.fileName}.replacement")
        writeOwnerOnly(replacement, bytes)
        Files.move(
            replacement,
            path,
            StandardCopyOption.ATOMIC_MOVE,
            StandardCopyOption.REPLACE_EXISTING,
        )
    }

    private fun setOwnerOnlyDirectory(path: Path) {
        if (supportsPosix(path)) {
            Files.setPosixFilePermissions(
                path,
                PosixFilePermissions.fromString("rwx------"),
            )
        }
    }

    private fun setOwnerOnlyFile(path: Path) {
        if (supportsPosix(path)) {
            Files.setPosixFilePermissions(
                path,
                PosixFilePermissions.fromString("rw-------"),
            )
        }
    }

    private fun supportsPosix(path: Path): Boolean =
        Files.getFileStore(path).supportsFileAttributeView("posix")

    private inline fun withProject(block: (Path) -> Unit) {
        withRoot { root ->
            Files.writeString(root.resolve("project.yaml"), "modules: []\n")
            block(root)
        }
    }

    private inline fun withRoot(block: (Path) -> Unit) {
        val root = createTempDirectory("stalwart-runtime-secrets-test").toRealPath()
        try {
            block(root)
        } finally {
            root.toFile().deleteRecursively()
        }
    }
}

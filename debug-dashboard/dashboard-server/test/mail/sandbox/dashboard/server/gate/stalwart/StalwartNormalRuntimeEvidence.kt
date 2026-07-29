package mail.sandbox.dashboard.server.gate.stalwart

import java.io.InputStream
import java.net.URI
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.security.MessageDigest
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

internal data class StalwartNormalRuntimeEnvironment(
    val baseUrl: URI,
) {
    companion object {
        fun load(
            environment: Map<String, String> = System.getenv(),
        ): StalwartNormalRuntimeEnvironment {
            StalwartGateActionSelection.requireLive(environment)
            require(
                environment.keys.filter { it.startsWith("STALWART_") }.toSet() ==
                    REQUIRED_ENVIRONMENT_KEYS,
            ) {
                "Normal-runtime live gate environment is invalid"
            }
            require(environment["STALWART_LIVE_TESTS"] == "1") {
                "STALWART_LIVE_TESTS=1 is required for the selected live gate"
            }
            require(
                environment["STALWART_BASE_URL"] ==
                    StalwartEndpointProfile.NORMAL_RUNTIME.baseUrl.toString(),
            ) {
                "STALWART_BASE_URL must select the exact normal loopback runtime"
            }
            return StalwartNormalRuntimeEnvironment(
                StalwartEndpointProfile.NORMAL_RUNTIME.baseUrl,
            )
        }
        private val REQUIRED_ENVIRONMENT_KEYS = setOf(
            "STALWART_BASE_URL",
            "STALWART_LIVE_TESTS",
        )
    }
}

internal data class StalwartSafeObjectProjection(
    val id: String,
    val objectType: String,
    val value: JsonObject,
)

internal data class StalwartManagementRuntimeEvidence(
    val accountId: String,
    val apiKeyId: String,
    val accountProjection: StalwartSafeObjectProjection,
    val apiKeyProjection: StalwartSafeObjectProjection,
    val credentialInventory: List<JsonObject>,
)

internal data class StalwartMigratedCredentialProjection(
    val slot: String,
    val projection: JsonObject,
)

internal data class StalwartDomainReference(
    val clientId: String,
    val domainName: String,
)

internal data class StalwartMigratedAccountEvidence(
    val accountProjection: JsonObject,
    val credentialProjections: List<StalwartMigratedCredentialProjection>,
    val domainReferences: List<StalwartDomainReference>,
) {
    val name: String =
        accountProjection.requiredString("name", "migrated Account evidence")
    val domainName: String = domainReferences.first().domainName
    val identity: Pair<String, String> = name to domainName
}

internal data class StalwartNormalRuntimeEvidenceSnapshot(
    val management: StalwartManagementRuntimeEvidence,
    val protectedAccountIds: List<String>,
    val oldRecoveryAuthenticationStatus: Int,
    val migratedAccounts: List<StalwartMigratedAccountEvidence>,
) {
    override fun toString(): String =
        "StalwartNormalRuntimeEvidenceSnapshot(values=validated,secrets=redacted)"
}

internal data class StalwartEvidenceProcessRequest(
    val argv: List<String>,
    val workingDirectory: Path,
    val environment: Map<String, String>,
)

internal interface StalwartEvidenceProcess {
    val stdout: InputStream
    val stderr: InputStream

    fun closeStdin()

    fun waitFor(timeoutMillis: Long): Boolean

    fun exitValue(): Int

    fun terminateTree(
        forcibly: Boolean,
        timeoutMillis: Long,
    ): Boolean
}

internal fun interface StalwartEvidenceProcessLauncher {
    fun start(request: StalwartEvidenceProcessRequest): StalwartEvidenceProcess
}

private object JdkStalwartEvidenceProcessLauncher :
    StalwartEvidenceProcessLauncher {
    override fun start(
        request: StalwartEvidenceProcessRequest,
    ): StalwartEvidenceProcess {
        val builder = ProcessBuilder(request.argv)
            .directory(request.workingDirectory.toFile())
            .redirectInput(ProcessBuilder.Redirect.PIPE)
            .redirectOutput(ProcessBuilder.Redirect.PIPE)
            .redirectError(ProcessBuilder.Redirect.PIPE)
        builder.environment().apply {
            clear()
            putAll(request.environment)
        }
        val process = builder.start()
        return object : StalwartEvidenceProcess {
            private val observedDescendants = linkedMapOf<Long, ProcessHandle>()
            override val stdout: InputStream = process.inputStream
            override val stderr: InputStream = process.errorStream

            override fun closeStdin() {
                process.outputStream.close()
            }

            override fun waitFor(timeoutMillis: Long): Boolean {
                val deadline = System.nanoTime() +
                    TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
                while (true) {
                    observeDescendants()
                    if (!process.isAlive) {
                        return true
                    }
                    val remaining = deadline - System.nanoTime()
                    if (remaining <= 0) {
                        return false
                    }
                    if (
                        process.waitFor(
                            minOf(
                                remaining,
                                DESCENDANT_OBSERVATION_INTERVAL_NANOS,
                            ),
                            TimeUnit.NANOSECONDS,
                        )
                    ) {
                        observeDescendants()
                        return true
                    }
                }
            }

            override fun exitValue(): Int = process.exitValue()

            override fun terminateTree(
                forcibly: Boolean,
                timeoutMillis: Long,
            ): Boolean {
                observeDescendants()
                if (forcibly) {
                    process.destroyForcibly()
                } else {
                    process.destroy()
                }
                observedDescendants.values.toList().asReversed()
                    .forEach { descendant ->
                        if (descendant.isAlive) {
                            if (forcibly) {
                                descendant.destroyForcibly()
                            } else {
                                descendant.destroy()
                            }
                        }
                    }
                val deadline = System.nanoTime() +
                    TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
                return observedDescendants.values.all { descendant ->
                    if (!descendant.isAlive) {
                        true
                    } else {
                        val remaining = deadline - System.nanoTime()
                        if (remaining <= 0) {
                            false
                        } else {
                            try {
                                descendant.onExit().get(
                                    remaining,
                                    TimeUnit.NANOSECONDS,
                                )
                                true
                            } catch (failure: InterruptedException) {
                                throw failure
                            } catch (_: Exception) {
                                false
                            }
                        }
                    }
                }
            }

            private fun observeDescendants() {
                buildList {
                    add(process.toHandle())
                    addAll(observedDescendants.values)
                }.forEach { root ->
                    root.descendants().use { descendants ->
                        descendants.forEach { descendant ->
                            observedDescendants.putIfAbsent(
                                descendant.pid(),
                                descendant,
                            )
                        }
                    }
                }
            }
        }
    }

    private val DESCENDANT_OBSERVATION_INTERVAL_NANOS =
        TimeUnit.MILLISECONDS.toNanos(50)
}

internal class StalwartNormalRuntimeEvidenceConsumer(
    private val launcher: StalwartEvidenceProcessLauncher =
        JdkStalwartEvidenceProcessLauncher,
    pythonExecutableResolver: () -> Path = ::resolveFixedPythonExecutable,
    private val commandTimeoutMillis: Long = 300_000,
    private val terminationTimeoutMillis: Long = 2_000,
) {
    private val pythonExecutable =
        validatePythonExecutable(pythonExecutableResolver())

    init {
        require(commandTimeoutMillis in 300_000..600_000) {
            "Normal-runtime evidence timeout is invalid"
        }
        require(terminationTimeoutMillis in 1..10_000) {
            "Normal-runtime evidence termination timeout is invalid"
        }
    }

    fun load(repositoryRoot: Path): StalwartNormalRuntimeEvidenceSnapshot {
        val root = validatePrimaryRepositoryRoot(repositoryRoot)
        val script = root.resolve(SCRIPT_PATH).normalize()
        val request = StalwartEvidenceProcessRequest(
            argv = listOf(
                pythonExecutable.toString(),
                script.toString(),
                COMMAND,
            ),
            workingDirectory = root,
            environment = SANITIZED_ENVIRONMENT,
        )
        val output = execute(request)
        return try {
            StalwartNormalRuntimeEvidence.decode(output)
        } finally {
            output.fill(0)
        }
    }

    private fun execute(request: StalwartEvidenceProcessRequest): ByteArray {
        val process = try {
            launcher.start(request)
        } catch (_: Exception) {
            throw IllegalArgumentException(
                "Normal-runtime evidence command could not start",
            )
        }
        val readers = Executors.newFixedThreadPool(2)
        val stdout = readers.submit<BoundedRead> {
            readBounded(process.stdout, MAXIMUM_STDOUT_BYTES)
        }
        val stderr = readers.submit<BoundedRead> {
            readBounded(process.stderr, MAXIMUM_STDERR_BYTES)
        }
        var returnedOutput: ByteArray? = null
        try {
            process.closeStdin()
            if (!process.waitFor(commandTimeoutMillis)) {
                terminate(process)
                throw IllegalArgumentException(
                    "Normal-runtime evidence command timed out",
                )
            }
            val stdoutResult = awaitRead(stdout, "stdout")
            val stderrResult = awaitRead(stderr, "stderr")
            if (
                process.exitValue() != 0 ||
                stdoutResult.oversized ||
                stderrResult.oversized ||
                stderrResult.bytes.isNotEmpty()
            ) {
                stdoutResult.bytes.fill(0)
                stderrResult.bytes.fill(0)
                throw IllegalArgumentException(
                    "Normal-runtime evidence command failed safely",
                )
            }
            stderrResult.bytes.fill(0)
            returnedOutput = stdoutResult.bytes
            return stdoutResult.bytes
        } catch (failure: InterruptedException) {
            terminateForciblySafely(process)
            Thread.currentThread().interrupt()
            throw failure
        } catch (failure: IllegalArgumentException) {
            terminateForciblySafely(process)
            throw failure
        } catch (_: Exception) {
            terminateForciblySafely(process)
            throw IllegalArgumentException(
                "Normal-runtime evidence command failed safely",
            )
        } finally {
            runCatching { process.stdout.close() }
            runCatching { process.stderr.close() }
            wipeCompletedRead(stderr)
            if (returnedOutput == null) {
                wipeCompletedRead(stdout)
            }
            stdout.cancel(true)
            stderr.cancel(true)
            readers.shutdownNow()
        }
    }

    private fun terminate(process: StalwartEvidenceProcess) {
        val descendantsExited = process.terminateTree(
            forcibly = false,
            timeoutMillis = terminationTimeoutMillis,
        )
        if (
            !process.waitFor(terminationTimeoutMillis) ||
            !descendantsExited
        ) {
            terminateForcibly(process)
        }
        require(
            process.terminateTree(
                forcibly = true,
                timeoutMillis = terminationTimeoutMillis,
            ),
        ) {
            "Normal-runtime evidence descendants did not terminate"
        }
    }

    private fun terminateForcibly(process: StalwartEvidenceProcess) {
        val descendantsExited = process.terminateTree(
            forcibly = true,
            timeoutMillis = terminationTimeoutMillis,
        )
        require(process.waitFor(terminationTimeoutMillis)) {
            "Normal-runtime evidence process did not terminate"
        }
        require(descendantsExited) {
            "Normal-runtime evidence descendants did not terminate"
        }
    }

    private fun terminateForciblySafely(process: StalwartEvidenceProcess) {
        try {
            terminateForcibly(process)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        } catch (_: Exception) {
            Unit
        }
    }

    private fun readBounded(
        input: InputStream,
        maximumBytes: Int,
    ): BoundedRead {
        val retained = ByteArray(maximumBytes)
        val buffer = ByteArray(8 * 1024)
        try {
            var total = 0L
            var retainedCount = 0
            var oversized = false
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                total += count
                if (total > maximumBytes) {
                    oversized = true
                }
                if (!oversized) {
                    buffer.copyInto(
                        destination = retained,
                        destinationOffset = retainedCount,
                        startIndex = 0,
                        endIndex = count,
                    )
                    retainedCount += count
                }
            }
            return BoundedRead(
                bytes = if (oversized) {
                    ByteArray(0)
                } else {
                    retained.copyOf(retainedCount)
                },
                oversized = oversized,
            )
        } finally {
            buffer.fill(0)
            retained.fill(0)
        }
    }

    private fun awaitRead(
        future: Future<BoundedRead>,
        streamName: String,
    ): BoundedRead =
        try {
            future.get(terminationTimeoutMillis, TimeUnit.MILLISECONDS)
        } catch (failure: InterruptedException) {
            throw failure
        } catch (_: Exception) {
            throw IllegalArgumentException(
                "Normal-runtime evidence $streamName was unavailable",
            )
        }

    private fun wipeCompletedRead(future: Future<BoundedRead>) {
        if (future.isDone && !future.isCancelled) {
            runCatching { future.get() }
                .getOrNull()
                ?.bytes
                ?.fill(0)
        }
    }

    private data class BoundedRead(
        val bytes: ByteArray,
        val oversized: Boolean,
    )

    companion object {
        internal const val MAXIMUM_STDOUT_BYTES = 4 * 1024 * 1024
        private const val MAXIMUM_STDERR_BYTES = 64 * 1024
        private const val COMMAND = "normal-runtime-evidence"
        private const val SCRIPT_PATH = "scripts/stalwart_v016.py"
        private val SANITIZED_ENVIRONMENT = mapOf(
            "LANG" to "C",
            "LC_ALL" to "C",
            "PATH" to
                "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
            "PYTHONDONTWRITEBYTECODE" to "1",
            "PYTHONHASHSEED" to "0",
            "PYTHONNOUSERSITE" to "1",
        )

        private fun resolveFixedPythonExecutable(): Path =
            listOf(
                Path.of("/opt/homebrew/bin/python3"),
                Path.of("/usr/bin/python3"),
            ).firstOrNull {
                Files.isRegularFile(it) && Files.isExecutable(it)
            }?.toRealPath()
                ?: throw IllegalArgumentException(
                    "Normal-runtime evidence Python executable is unavailable",
                )

        private fun validatePythonExecutable(requested: Path): Path {
            val normalized = requested.normalize()
            require(
                normalized.isAbsolute &&
                    normalized.toString() == requested.toString(),
            ) {
                "Normal-runtime evidence Python executable is invalid"
            }
            return normalized
        }

        private fun validatePrimaryRepositoryRoot(requested: Path): Path {
            val root = requested.toAbsolutePath().normalize()
            require(
                root == requested &&
                    Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS) &&
                    !Files.isSymbolicLink(root) &&
                    root.toRealPath() == root,
            ) {
                "Normal-runtime evidence repository root is invalid"
            }
            val git = root.resolve(".git")
            val scripts = root.resolve("scripts")
            val script = root.resolve(SCRIPT_PATH)
            val dashboard = root.resolve("debug-dashboard")
            val marker = dashboard.resolve("project.yaml")
            require(
                    Files.isDirectory(git, LinkOption.NOFOLLOW_LINKS) &&
                    !Files.isSymbolicLink(git) &&
                    Files.isDirectory(scripts, LinkOption.NOFOLLOW_LINKS) &&
                    !Files.isSymbolicLink(scripts) &&
                    scripts.toRealPath(LinkOption.NOFOLLOW_LINKS) == scripts &&
                    Files.isDirectory(dashboard, LinkOption.NOFOLLOW_LINKS) &&
                    !Files.isSymbolicLink(dashboard) &&
                    Files.isRegularFile(script, LinkOption.NOFOLLOW_LINKS) &&
                    !Files.isSymbolicLink(script) &&
                    script.toRealPath(LinkOption.NOFOLLOW_LINKS) == script &&
                    Files.isRegularFile(marker, LinkOption.NOFOLLOW_LINKS) &&
                    !Files.isSymbolicLink(marker),
            ) {
                "Normal-runtime evidence repository root is invalid"
            }
            return root
        }
    }
}

internal object StalwartNormalRuntimeEvidence {
    fun load(repositoryRoot: Path): StalwartNormalRuntimeEvidenceSnapshot =
        StalwartNormalRuntimeEvidenceConsumer().load(repositoryRoot)

    fun decode(bytes: ByteArray): StalwartNormalRuntimeEvidenceSnapshot {
        val payload = decodeDigestEnvelope(
            bytes,
            "normal-runtime evidence",
        )
        require(
            payload.keys == setOf(
                "management",
                "migrated_accounts",
                "old_recovery_auth_status",
                "protected_account_ids",
                "schema",
            ) &&
                payload.requiredString(
                    "schema",
                    "normal-runtime evidence",
                ) == SCHEMA,
        ) {
            "Normal-runtime evidence payload is invalid"
        }
        val management = decodeManagement(
            payload.requiredObject("management", "normal-runtime evidence"),
        )
        val protectedAccountIds = payload.requiredArray(
            "protected_account_ids",
            "normal-runtime evidence",
        ).map { item ->
            item.requiredSafeId("protected Account ID")
        }
        require(protectedAccountIds == listOf(management.accountId)) {
            "Normal-runtime protected Account evidence is invalid"
        }
        val status = payload.requiredNativeInt(
            "old_recovery_auth_status",
            "normal-runtime evidence",
        )
        require(status == 401 || status == 403) {
            "Normal-runtime recovery retirement evidence is invalid"
        }
        val migrated = payload.requiredArray(
            "migrated_accounts",
            "normal-runtime evidence",
        ).map { value ->
            decodeMigratedAccount(value)
        }
        val domainNamesByClient = mutableMapOf<String, String>()
        val clientsByDomainName = mutableMapOf<String, String>()
        migrated.flatMap { it.domainReferences }.forEach { reference ->
            require(
                domainNamesByClient.putIfAbsent(
                    reference.clientId,
                    reference.domainName,
                ) in setOf(null, reference.domainName) &&
                    clientsByDomainName.putIfAbsent(
                        reference.domainName,
                        reference.clientId,
                    ) in setOf(null, reference.clientId),
            ) {
                "Normal-runtime Domain reference evidence is invalid"
            }
        }
        require(
            migrated.map { it.identity }.size ==
                migrated.map { it.identity }.toSet().size,
        ) {
            "Normal-runtime migrated Account identity evidence is invalid"
        }
        return StalwartNormalRuntimeEvidenceSnapshot(
            management = management,
            protectedAccountIds = protectedAccountIds,
            oldRecoveryAuthenticationStatus = status,
            migratedAccounts = migrated,
        )
    }

    fun decodeDigestEnvelope(
        bytes: ByteArray,
        label: String,
    ): JsonObject {
        require(
            bytes.isNotEmpty() &&
                bytes.last() == '\n'.code.toByte() &&
                bytes.count { it == '\n'.code.toByte() } == 1,
        ) {
            "$label is invalid"
        }
        val text = decodeUtf8(bytes, label)
        val envelope = runCatching {
            Json.parseToJsonElement(text.dropLast(1)).jsonObject
        }.getOrElse {
            throw IllegalArgumentException("$label is invalid")
        }
        require(envelope.keys == setOf("payload", "payload_sha256")) {
            "$label is invalid"
        }
        val payload = envelope["payload"] as? JsonObject
            ?: throw IllegalArgumentException("$label is invalid")
        val digest = (envelope["payload_sha256"] as? JsonPrimitive)
            ?.takeIf(JsonPrimitive::isString)
            ?.content
            ?.takeIf { it.matches(SHA256_PATTERN) }
            ?: throw IllegalArgumentException("$label is invalid")
        val canonicalPayload = StalwartRoutingCanonicalJson.encode(payload)
            .encodeToByteArray()
        require(
            MessageDigest.isEqual(
                digest.encodeToByteArray(),
                sha256(canonicalPayload).encodeToByteArray(),
            ) &&
                (
                    StalwartRoutingCanonicalJson.encode(envelope) + "\n"
                    ).encodeToByteArray() contentEquals bytes,
        ) {
            "$label is invalid"
        }
        return payload
    }

    private fun decodeManagement(
        value: JsonObject,
    ): StalwartManagementRuntimeEvidence {
        require(
            value.keys == setOf(
                "account_id",
                "account_projection",
                "api_key_id",
                "api_key_projection",
                "credential_inventory",
            ),
        ) {
            "Normal-runtime management evidence is invalid"
        }
        val accountId = value.requiredSafeId(
            "account_id",
            "normal-runtime management evidence",
        )
        val apiKeyId = value.requiredSafeId(
            "api_key_id",
            "normal-runtime management evidence",
        )
        val accountProjection = decodeSafeObject(
            value.requiredObject(
                "account_projection",
                "normal-runtime management evidence",
            ),
            expectedType = "Account",
            expectedId = accountId,
        )
        val apiKeyProjection = decodeSafeObject(
            value.requiredObject(
                "api_key_projection",
                "normal-runtime management evidence",
            ),
            expectedType = "ApiKey",
            expectedId = apiKeyId,
        )
        val inventory = value.requiredArray(
            "credential_inventory",
            "normal-runtime management evidence",
        ).map { item ->
            val projection = item as? JsonObject
                ?: throw IllegalArgumentException(
                    "Normal-runtime management credential inventory is invalid",
                )
            require(
                projection.keys == setOf(
                    "account_id",
                    "allowed_ips",
                    "credential_id",
                    "credential_type",
                    "description",
                    "permissions",
                ) &&
                    projection.requiredSafeId(
                        "account_id",
                        "normal-runtime management credential inventory",
                    ) == accountId &&
                    projection.requiredSafeId(
                        "credential_id",
                        "normal-runtime management credential inventory",
                    ) == apiKeyId &&
                    projection.requiredString(
                        "credential_type",
                        "normal-runtime management credential inventory",
                    ) == "ApiKey" &&
                    projection["allowed_ips"] is JsonObject &&
                    projection["permissions"] is JsonObject &&
                    projection["description"] is JsonPrimitive &&
                    projection["description"]!!.jsonPrimitive.isString,
            ) {
                "Normal-runtime management credential inventory is invalid"
            }
            requireNoSensitiveFields(projection)
            projection
        }
        require(
            inventory.size == 1 &&
                "credentials" !in accountProjection.value &&
                apiKeyProjection.value.keys == setOf(
                    "accountId",
                    "allowedIps",
                    "credentialType",
                    "description",
                    "permissions",
                ) &&
                apiKeyProjection.value.requiredSafeId(
                    "accountId",
                    "normal-runtime management API-key projection",
                ) == accountId &&
                apiKeyProjection.value.requiredString(
                    "credentialType",
                    "normal-runtime management API-key projection",
                ) == "ApiKey" &&
                apiKeyProjection.value["allowedIps"] ==
                inventory.single()["allowed_ips"] &&
                apiKeyProjection.value["description"] ==
                inventory.single()["description"] &&
                apiKeyProjection.value["permissions"] ==
                inventory.single()["permissions"],
        ) {
            "Normal-runtime management credential inventory is invalid"
        }
        return StalwartManagementRuntimeEvidence(
            accountId = accountId,
            apiKeyId = apiKeyId,
            accountProjection = accountProjection,
            apiKeyProjection = apiKeyProjection,
            credentialInventory = inventory,
        )
    }

    private fun decodeSafeObject(
        value: JsonObject,
        expectedType: String,
        expectedId: String,
    ): StalwartSafeObjectProjection {
        require(value.keys == setOf("id", "object_type", "value")) {
            "Normal-runtime safe object evidence is invalid"
        }
        val id = value.requiredSafeId(
            "id",
            "normal-runtime safe object evidence",
        )
        val objectType = value.requiredString(
            "object_type",
            "normal-runtime safe object evidence",
        )
        val projection = value.requiredObject(
            "value",
            "normal-runtime safe object evidence",
        )
        require(id == expectedId && objectType == expectedType) {
            "Normal-runtime safe object evidence is invalid"
        }
        requireNoSensitiveFields(projection)
        return StalwartSafeObjectProjection(id, objectType, projection)
    }

    private fun decodeMigratedAccount(
        value: JsonElement,
    ): StalwartMigratedAccountEvidence {
        val account = value as? JsonObject
            ?: throw IllegalArgumentException(
                "Normal-runtime migrated Account evidence is invalid",
            )
        require(
            account.keys == setOf(
                "account_projection",
                "credential_projections",
                "domain_references",
            ),
        ) {
            "Normal-runtime migrated Account evidence is invalid"
        }
        val accountProjection = account.requiredObject(
            "account_projection",
            "normal-runtime migrated Account evidence",
        )
        validateMigratedAccountProjection(accountProjection)
        requireNoSensitiveFields(accountProjection)
        val credentials = account.requiredArray(
            "credential_projections",
            "normal-runtime migrated Account evidence",
        ).map { item ->
            val credential = item as? JsonObject
                ?: throw IllegalArgumentException(
                    "Normal-runtime migrated credential evidence is invalid",
                )
            require(credential.keys == setOf("projection", "slot")) {
                "Normal-runtime migrated credential evidence is invalid"
            }
            val slot = credential.requiredString(
                "slot",
                "normal-runtime migrated credential evidence",
            )
            require(slot == "0") {
                "Normal-runtime migrated credential evidence is invalid"
            }
            val projection = credential.requiredObject(
                "projection",
                "normal-runtime migrated credential evidence",
            )
            require(
                projection.keys in setOf(
                    setOf("@type", "secret"),
                    setOf("@type", "otpAuth", "secret"),
                ) &&
                    projection.requiredString(
                        "@type",
                        "normal-runtime migrated credential evidence",
                    ) == "Password",
            ) {
                "Normal-runtime migrated credential evidence is invalid"
            }
            requireMaskedCredentialFields(projection)
            StalwartMigratedCredentialProjection(slot, projection)
        }
        require(credentials.size <= 1) {
            "Normal-runtime migrated credential evidence is invalid"
        }
        val references = account.requiredArray(
            "domain_references",
            "normal-runtime migrated Account evidence",
        ).map { item ->
            val reference = item as? JsonObject
                ?: throw IllegalArgumentException(
                    "Normal-runtime Domain reference evidence is invalid",
                )
            require(reference.keys == setOf("client_id", "domain_name")) {
                "Normal-runtime Domain reference evidence is invalid"
            }
            StalwartDomainReference(
                clientId = reference.requiredString(
                    "client_id",
                    "normal-runtime Domain reference evidence",
                ).also { clientId ->
                    require(clientId.matches(DOMAIN_CLIENT_ID_PATTERN)) {
                        "Normal-runtime Domain reference evidence is invalid"
                    }
                },
                domainName = reference.requiredString(
                    "domain_name",
                    "normal-runtime Domain reference evidence",
                ),
            )
        }
        require(
            references.map { it.clientId }.size ==
                references.map { it.clientId }.toSet().size &&
                references.map { it.domainName }.size ==
                references.map { it.domainName }.toSet().size &&
                references.map { it.clientId } ==
                referencedDomainClientIds(accountProjection),
        ) {
            "Normal-runtime Domain reference evidence is invalid"
        }
        return StalwartMigratedAccountEvidence(
            accountProjection = accountProjection,
            credentialProjections = credentials,
            domainReferences = references,
        )
    }

    private fun validateMigratedAccountProjection(value: JsonObject) {
        val required = setOf(
            "@type",
            "aliases",
            "domainId",
            "memberGroupIds",
            "name",
            "quotas",
        )
        val optional = setOf("description")
        require(
            value.keys.containsAll(required) &&
                value.keys.all { it in required || it in optional } &&
                value.requiredString(
                    "@type",
                    "normal-runtime migrated Account evidence",
                ) == "User",
        ) {
            "Normal-runtime migrated Account evidence is invalid"
        }
        value.requiredString("name", "normal-runtime migrated Account evidence")
        value["description"]?.let {
            require(
                it is JsonPrimitive && it.isString && it.content.isNotEmpty(),
            ) {
                "Normal-runtime migrated Account evidence is invalid"
            }
        }
        val aliases = value.requiredObject(
            "aliases",
            "normal-runtime migrated Account evidence",
        )
        require(
            aliases.keys == (0 until aliases.size).map(Int::toString).toSet(),
        ) {
            "Normal-runtime migrated Account evidence is invalid"
        }
        aliases.forEach { (_, aliasValue) ->
            val alias = aliasValue as? JsonObject
                ?: throw IllegalArgumentException(
                    "Normal-runtime migrated Account evidence is invalid",
                )
            require(alias.keys == setOf("domainId", "name")) {
                "Normal-runtime migrated Account evidence is invalid"
            }
            alias.requiredString(
                "name",
                "normal-runtime migrated Account evidence",
            )
        }
        require(
            value.requiredObject(
                "memberGroupIds",
                "normal-runtime migrated Account evidence",
            ).isEmpty(),
        ) {
            "Normal-runtime migrated Account evidence is invalid"
        }
        val quotas = value.requiredObject(
            "quotas",
            "normal-runtime migrated Account evidence",
        )
        require(quotas.keys.isEmpty() || quotas.keys == setOf("maxDiskQuota")) {
            "Normal-runtime migrated Account evidence is invalid"
        }
        quotas["maxDiskQuota"]?.let { quota ->
            val primitive = quota as? JsonPrimitive
                ?: throw IllegalArgumentException(
                    "Normal-runtime migrated Account evidence is invalid",
                )
            require(
                !primitive.isString &&
                    primitive.content.matches(POSITIVE_INTEGER_PATTERN),
            ) {
                "Normal-runtime migrated Account evidence is invalid"
            }
        }
    }

    private fun referencedDomainClientIds(
        accountProjection: JsonObject,
    ): List<String> {
        val referenced = linkedSetOf<String>()

        fun record(value: JsonElement) {
            val reference = (value as? JsonPrimitive)
                ?.takeIf(JsonPrimitive::isString)
                ?.content
                ?.takeIf { it.startsWith("#") }
                ?.drop(1)
                ?.takeIf { it.matches(DOMAIN_CLIENT_ID_PATTERN) }
                ?: throw IllegalArgumentException(
                    "Normal-runtime Domain reference evidence is invalid",
                )
            referenced += reference
        }

        fun walk(value: JsonElement) {
            when (value) {
                is JsonObject -> value.keys.sorted().forEach { name ->
                    require(!name.startsWith("#")) {
                        "Normal-runtime Domain reference evidence is invalid"
                    }
                    val child = value.getValue(name)
                    if (name == "domainId") {
                        record(child)
                    } else {
                        walk(child)
                    }
                }
                is JsonArray -> value.forEach(::walk)
                is JsonPrimitive -> require(
                    !value.isString || !value.content.startsWith("#"),
                ) {
                    "Normal-runtime Domain reference evidence is invalid"
                }
                JsonNull -> Unit
            }
        }

        record(accountProjection.getValue("domainId"))
        walk(accountProjection)
        return referenced.toList()
    }

    private fun requireNoSensitiveFields(value: JsonElement) {
        when (value) {
            is JsonObject -> value.forEach { (name, child) ->
                require(name.lowercase() !in SENSITIVE_FIELD_NAMES) {
                    "Normal-runtime evidence contains unsafe credential material"
                }
                requireNoSensitiveFields(child)
            }

            is JsonArray -> value.forEach(::requireNoSensitiveFields)
            is JsonPrimitive, JsonNull -> Unit
        }
    }

    private fun requireMaskedCredentialFields(value: JsonObject) {
        value.forEach { (name, child) ->
            val normalized = name.lowercase()
            require(normalized !in SENSITIVE_FIELD_NAMES || name in MASKED_FIELDS) {
                "Normal-runtime evidence contains unsafe credential material"
            }
            if (name in MASKED_FIELDS) {
                require(
                    (child as? JsonPrimitive)
                        ?.takeIf(JsonPrimitive::isString)
                        ?.content == REDACTED_SECRET,
                ) {
                    "Normal-runtime evidence contains unsafe credential material"
                }
            }
        }
    }

    private fun decodeUtf8(bytes: ByteArray, label: String): String =
        try {
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString()
        } catch (_: Exception) {
            throw IllegalArgumentException("$label is invalid")
        }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256")
            .digest(bytes)
            .joinToString(separator = "") { "%02x".format(it) }

    private val SHA256_PATTERN = Regex("[0-9a-f]{64}")
    private val SAFE_ID_PATTERN = Regex("[A-Za-z0-9_-]{1,255}")
    private val DOMAIN_CLIENT_ID_PATTERN = Regex("create-(0|[1-9][0-9]*)")
    private val POSITIVE_INTEGER_PATTERN = Regex("[1-9][0-9]*")
    private val MASKED_FIELDS = setOf("otpAuth", "secret")
    private val SENSITIVE_FIELD_NAMES = setOf(
        "access_token",
        "accesstoken",
        "credentials",
        "otpauth",
        "password",
        "private_key",
        "privatekey",
        "secret",
        "secrets",
        "token",
    )
    private const val REDACTED_SECRET = "****"
    private const val SCHEMA =
        "mail-sandbox.stalwart-v016-normal-runtime-evidence.v2"
}

private fun JsonObject.requiredObject(
    name: String,
    label: String,
): JsonObject =
    this[name] as? JsonObject
        ?: throw IllegalArgumentException("$label is invalid")

private fun JsonObject.requiredArray(
    name: String,
    label: String,
): JsonArray =
    this[name] as? JsonArray
        ?: throw IllegalArgumentException("$label is invalid")

private fun JsonObject.requiredString(
    name: String,
    label: String,
): String =
    (this[name] as? JsonPrimitive)
        ?.takeIf(JsonPrimitive::isString)
        ?.content
        ?.takeIf(String::isNotBlank)
        ?: throw IllegalArgumentException("$label is invalid")

private fun JsonObject.requiredSafeId(
    name: String,
    label: String,
): String =
    requiredString(name, label).also {
        require(it.matches(Regex("[A-Za-z0-9_-]{1,255}"))) {
            "$label is invalid"
        }
    }

private fun JsonElement.requiredSafeId(label: String): String =
    (this as? JsonPrimitive)
        ?.takeIf(JsonPrimitive::isString)
        ?.content
        ?.takeIf { it.matches(Regex("[A-Za-z0-9_-]{1,255}")) }
        ?: throw IllegalArgumentException("$label is invalid")

private fun JsonObject.requiredNativeInt(
    name: String,
    label: String,
): Int {
    val primitive = this[name] as? JsonPrimitive
        ?: throw IllegalArgumentException("$label is invalid")
    require(!primitive.isString && primitive.content.matches(Regex("0|[1-9][0-9]*"))) {
        "$label is invalid"
    }
    return primitive.content.toIntOrNull()
        ?: throw IllegalArgumentException("$label is invalid")
}

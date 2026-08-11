package mail.sandbox.dashboard.server.local

import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import mail.sandbox.dashboard.contract.LogResponse
import mail.sandbox.dashboard.contract.LogService
import mail.sandbox.dashboard.server.gate.dovecot.DovecotDockerRouting

private const val ROOT_COMPOSE = "docker-compose.yml"

internal data class ComposeLogRequest(
    val argv: List<String>,
    val timeout: Duration = Duration.ofSeconds(15),
    val maximumOutputBytes: Int = 4 * 1024 * 1024,
)

internal data class ComposeLogResult(
    val exitCode: Int?,
    val stdout: String,
    val stderr: String = "",
    val timedOut: Boolean = false,
)

internal fun interface ComposeLogRunner {
    fun run(request: ComposeLogRequest): ComposeLogResult
}

internal data class DashboardLogAccount(
    val address: String,
    val providerAccountId: String? = null,
)

internal data class DashboardLogCursor(
    val lines: List<String>,
)

internal interface DashboardLogSource {
    fun read(
        service: LogService,
        account: DashboardLogAccount? = null,
        limit: Int = 500,
    ): LogResponse

    fun snapshot(
        service: LogService,
        account: DashboardLogAccount,
        limit: Int = 500,
    ): DashboardLogCursor = DashboardLogCursor(read(service, account, limit).lines)

    fun readAfter(
        service: LogService,
        account: DashboardLogAccount,
        cursor: DashboardLogCursor,
        limit: Int = 500,
    ): LogResponse {
        val current = read(service, account, limit)
        val overlap = (minOf(cursor.lines.size, current.lines.size) downTo 0)
            .first { size -> cursor.lines.takeLast(size) == current.lines.take(size) }
        return current.copy(lines = current.lines.drop(overlap))
    }
}

internal class DockerComposeLogSource(
    private val repositoryRoot: Path,
    private val runner: ComposeLogRunner = JvmComposeLogRunner(repositoryRoot),
) : DashboardLogSource {
    override fun read(
        service: LogService,
        account: DashboardLogAccount?,
        limit: Int,
    ): LogResponse {
        require(limit in 1..MAX_LIMIT) { "Log line limit must be between 1 and $MAX_LIMIT" }
        val lineFilter = account?.let { selector -> accountFilter(service, selector) }
        val responseLimit = if (account == null) limit else minOf(limit, ACCOUNT_LOG_LIMIT)
        if (service == LogService.ALL) {
            val linesByService = PROVIDER_SERVICES.map { providerService ->
                read(providerService, account, limit).lines.map { line ->
                    "[${providerService.name.lowercase()}] $line"
                }
            }
            return LogResponse(
                service = service,
                account = account?.address,
                lines = fairTail(linesByService, responseLimit),
            )
        }

        val sourceLimit = if (account == null) limit else ACCOUNT_SOURCE_LIMIT
        val result = runner.run(ComposeLogRequest(argv = command(service, sourceLimit)))
        check(!result.timedOut && result.exitCode == 0) {
            val detail = result.stderr.trim().take(240).ifEmpty { "exit ${result.exitCode}" }
            "Could not read local provider logs: $detail"
        }
        val lines = result.stdout.lineSequence()
            .map { it.removeSuffix("\r") }
            .filter(String::isNotEmpty)
            .let { sequence ->
                if (lineFilter == null) sequence else sequence.filter(lineFilter)
            }
            .toList()
            .takeLast(responseLimit)
        return LogResponse(service = service, account = account?.address, lines = lines)
    }

    private fun accountFilter(
        service: LogService,
        account: DashboardLogAccount,
    ): (String) -> Boolean {
        requireAddress(account.address)
        val address = accountAddress(account.address)
        val numericAccountId = account.providerAccountId?.let(::decodeStalwartAccountId)
        val structuredId = numericAccountId
            ?.takeIf { service == LogService.STALWART }
            ?.let(::structuredAccountId)
        return { line ->
            address.containsMatchIn(line) ||
                structuredId?.containsMatchIn(line) == true
        }
    }

    private fun accountAddress(address: String): Regex = Regex(
        "(?<![A-Za-z0-9._+%@-])${Regex.escape(address)}(?![A-Za-z0-9._+%@-])",
        RegexOption.IGNORE_CASE,
    )

    private fun structuredAccountId(accountId: ULong): Regex = Regex(
        "(?:^|[\\s,{])accountId = $accountId(?=$|[\\s,}])",
    )

    private fun command(service: LogService, limit: Int): List<String> = when (service) {
        LogService.DOVECOT -> rootCommand("dovecot", limit)
        LogService.POSTFIX -> rootCommand("postfix", limit)
        LogService.OAUTH2 -> rootCommand("oauth2-mock", limit)
        LogService.STALWART -> rootCommand("stalwart", limit)

        LogService.ALL -> error("ALL is expanded before command construction")
    }

    private fun rootCommand(service: String, limit: Int): List<String> = listOf(
        "docker", "compose", "-f", repositoryRoot.resolve(ROOT_COMPOSE).toString(),
        "logs", "--no-color", "--tail", limit.toString(), service,
    )

    private fun fairTail(sources: List<List<String>>, limit: Int): List<String> {
        val quotas = IntArray(sources.size)
        var remaining = limit
        while (remaining > 0) {
            var progressed = false
            sources.indices.forEach { index ->
                if (remaining > 0 && quotas[index] < sources[index].size) {
                    quotas[index]++
                    remaining--
                    progressed = true
                }
            }
            if (!progressed) break
        }
        return buildList {
            sources.forEachIndexed { index, lines ->
                addAll(lines.takeLast(quotas[index]))
            }
        }
    }

    private fun requireAddress(value: String) {
        require(ADDRESS.matches(value)) {
            "Log account filter must be a canonical local.test address"
        }
    }

    private companion object {
        const val DEFAULT_LIMIT = 500
        const val ACCOUNT_LOG_LIMIT = 500
        const val ACCOUNT_SOURCE_LIMIT = 2_000
        const val MAX_LIMIT = 2_000
        val ADDRESS = Regex("[a-z0-9][a-z0-9._+%-]{0,63}@local\\.test")
        val PROVIDER_SERVICES = listOf(
            LogService.DOVECOT,
            LogService.POSTFIX,
            LogService.OAUTH2,
            LogService.STALWART,
        )
    }
}

internal fun decodeStalwartAccountId(value: String): ULong {
    require(value.isNotEmpty()) { "Stalwart Account ID is absent" }
    require(value == "a" || value.first() != 'a') {
        "Stalwart Account ID is not canonically encoded"
    }

    var decoded = 0UL
    value.forEach { character ->
        val index = STALWART_ID_ALPHABET.indexOf(character)
        require(index >= 0) { "Stalwart Account ID contains an invalid character" }
        val digit = index.toULong()
        require(decoded <= (ULong.MAX_VALUE - digit) / STALWART_ID_RADIX) {
            "Stalwart Account ID exceeds the unsigned 64-bit range"
        }
        decoded = decoded * STALWART_ID_RADIX + digit
    }
    return decoded
}

private const val STALWART_ID_ALPHABET = "abcdefghijklmnopqrstuvwxyz792013"
private const val STALWART_ID_RADIX = 32UL

internal class JvmComposeLogRunner(
    private val repositoryRoot: Path,
    private val dockerRouting: DovecotDockerRouting = DovecotDockerRouting.localDefault(),
) : ComposeLogRunner {
    override fun run(request: ComposeLogRequest): ComposeLogResult {
        require(Files.isRegularFile(repositoryRoot.resolve("docker-compose.yml"))) {
            "Compose project root is invalid"
        }
        require(isApproved(request.argv)) { "Compose log command is not approved" }
        require(
            !request.timeout.isZero && !request.timeout.isNegative &&
                request.timeout <= Duration.ofSeconds(30) &&
                request.maximumOutputBytes in 1..8 * 1024 * 1024,
        ) {
            "Compose log request bounds are invalid"
        }
        val process = ProcessBuilder(request.argv)
            .directory(repositoryRoot.toFile())
            .also { builder -> dockerRouting.applyTo(builder.environment()) }
            .start()
        process.outputStream.close()
        val readers = Executors.newFixedThreadPool(2) { runnable ->
            Thread(runnable, "dashboard-log-reader").also { it.isDaemon = true }
        }
        val stdout = readers.submit(Callable {
            process.inputStream.use { it.readNBytes(request.maximumOutputBytes + 1) }
        })
        val stderr = readers.submit(Callable {
            process.errorStream.use { it.readNBytes(request.maximumOutputBytes + 1) }
        })
        return try {
            val completed = process.waitFor(request.timeout.toMillis(), TimeUnit.MILLISECONDS)
            if (!completed) {
                process.destroyForcibly()
                process.waitFor(2, TimeUnit.SECONDS)
            }
            val stdoutBytes = stdout.get(3, TimeUnit.SECONDS)
            val stderrBytes = stderr.get(3, TimeUnit.SECONDS)
            check(
                stdoutBytes.size <= request.maximumOutputBytes &&
                    stderrBytes.size <= request.maximumOutputBytes,
            ) {
                "Compose log output exceeded the local dashboard limit"
            }
            ComposeLogResult(
                exitCode = if (completed) process.exitValue() else null,
                stdout = stdoutBytes.toString(Charsets.UTF_8),
                stderr = stderrBytes.toString(Charsets.UTF_8),
                timedOut = !completed,
            )
        } finally {
            stdout.cancel(true)
            stderr.cancel(true)
            readers.shutdownNow()
            if (process.isAlive) process.destroyForcibly()
        }
    }

    private fun isApproved(argv: List<String>): Boolean {
        return argv.size == 9 &&
            argv.take(3) == listOf("docker", "compose", "-f") &&
            argv[3] == repositoryRoot.resolve(ROOT_COMPOSE).toString() &&
            argv.subList(4, 7) == listOf("logs", "--no-color", "--tail") &&
            argv[7].toIntOrNull() in 1..2_000 &&
            argv[8] in setOf("dovecot", "postfix", "oauth2-mock", "stalwart")
    }
}

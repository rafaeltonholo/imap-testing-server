package mail.sandbox.dashboard.server.web

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.security.MessageDigest
import java.util.Collections
import kotlin.io.path.isDirectory
import kotlin.io.path.isRegularFile

class WebAsset(
    bytes: ByteArray,
    val contentType: String,
    val sha256: String,
) {
    private val snapshot = bytes.copyOf()

    val bytes: ByteArray
        get() = snapshot.copyOf()
}

internal data class PinnedClasspathAsset(
    val publicFileName: String,
    val classpathResourceName: String,
    val expectedSha256: String,
)

class WebAssetBundle private constructor(
    val entryAssetPath: String,
    val html: String,
    assets: Map<String, WebAsset>,
) {
    private val assets = Collections.unmodifiableMap(LinkedHashMap(assets))
    val assetPaths: Set<String> =
        Collections.unmodifiableSet(LinkedHashSet(this.assets.keys))

    fun asset(publicPath: String): WebAsset? = assets[publicPath]

    fun requireAsset(publicPath: String): WebAsset =
        requireNotNull(asset(publicPath)) { "Asset is not in the validated manifest: $publicPath" }

    companion object {
        private const val ASSETS_ENV = "DASHBOARD_WEB_ASSETS"
        private const val RESOURCES_ENV = "DASHBOARD_WEB_RESOURCES"
        private const val ENTRY_ENV = "DASHBOARD_WEB_ENTRY"
        private const val RESOURCE_PACKAGE = "mail.sandbox.dashboard.web.generated.resources"
        private const val RESOURCE_PREFIX = "/assets/composeResources/$RESOURCE_PACKAGE/"
        private const val INDEX_RESOURCE = "web/index.html"
        private const val ENTRY_TOKEN = "{{DASHBOARD_WEB_ENTRY}}"
        private const val GATE_MARKER_ROUTE = "${RESOURCE_PREFIX}files/gate-proof.txt"
        private const val GATE_MARKER_SHA256 =
            "7b0f843ebd49d2709bcd8e3d1021db98e68413823647895d8377a6657f5e6960"
        private const val SKIKO_MJS_SHA256 =
            "7fa5652ceb6343affed0360d2a8e5e35dbce1dff6192b2268c7519861af2dff4"
        private const val SKIKO_WASM_SHA256 =
            "46caff5f783599bd1c5d3e5e87959d7cb5102c515aac671c9280664368e71dab"
        private const val JODA_SHA256 =
            "a716a37f4c3bb47f8795688e1cd6451130a08d825d8a6df664ef72b349ec445b"

        fun fromEnvironment(
            environment: Map<String, String> = System.getenv(),
            projectRoot: Path = Paths.get(System.getProperty("user.dir")).toRealPath(),
            classLoader: ClassLoader = WebAssetBundle::class.java.classLoader,
        ): WebAssetBundle {
            fun required(name: String): String =
                environment[name]?.takeIf { it.isNotBlank() }
                    ?: throw IllegalArgumentException("Required environment variable $name is absent")

            return load(
                projectRoot = projectRoot,
                linkerDirectory = Paths.get(required(ASSETS_ENV)),
                composeResourcesDirectory = Paths.get(required(RESOURCES_ENV)),
                entryFileName = required(ENTRY_ENV),
                classLoader = classLoader,
            )
        }

        internal fun load(
            projectRoot: Path,
            linkerDirectory: Path,
            composeResourcesDirectory: Path,
            entryFileName: String,
            classLoader: ClassLoader = WebAssetBundle::class.java.classLoader,
            runtimeResources: List<PinnedClasspathAsset> = productionWebRuntimeResources(),
        ): WebAssetBundle = Loader(
            projectRoot = projectRoot,
            linkerDirectory = linkerDirectory,
            composeResourcesDirectory = composeResourcesDirectory,
            entryFileName = entryFileName,
            classLoader = classLoader,
            runtimeResources = runtimeResources,
        ).load()
    }

    private class Loader(
        projectRoot: Path,
        linkerDirectory: Path,
        composeResourcesDirectory: Path,
        private val entryFileName: String,
        private val classLoader: ClassLoader,
        runtimeResources: List<PinnedClasspathAsset>,
    ) {
        private val projectRoot = requireCanonicalDirectory(projectRoot, "project root")
        private val linkerDirectory = requireCanonicalDirectory(
            linkerDirectory,
            "linker directory",
            this.projectRoot,
        )
        private val composeResourcesDirectory = requireCanonicalDirectory(
            composeResourcesDirectory,
            "Compose resource directory",
            this.projectRoot,
        )
        private val runtimeResources = runtimeResources.associateUniqueByPublicName()
        private val manifest = linkedMapOf<String, WebAsset>()
        private val origins = mutableMapOf<String, AssetOrigin>()
        private val pendingCode = ArrayDeque<String>()
        private val parsedCode = mutableSetOf<String>()
        private var sawJodaImport = false

        fun load(): WebAssetBundle {
            validateEntryName()
            addCodeAsset(entryFileName)

            while (pendingCode.isNotEmpty()) {
                val publicName = pendingCode.removeFirst()
                if (!parsedCode.add(publicName)) continue
                val asset = manifest.getValue(assetRoute(publicName))
                ModuleReferenceScanner(asset.bytes.decodeToString()).references().forEach { reference ->
                    resolveReference(publicName, reference)
                }
            }

            addComposeResources()
            validateRequiredRuntime()
            val entryPath = assetRoute(entryFileName)
            val html = loadAndRenderIndex(entryPath)
            return WebAssetBundle(entryPath, html, manifest.toMap())
        }

        private fun validateEntryName() {
            val parsed = runCatching { Paths.get(entryFileName) }.getOrNull()
            require(
                entryFileName.isNotBlank() &&
                    entryFileName.endsWith(".mjs") &&
                    parsed != null &&
                    parsed.fileName.toString() == entryFileName &&
                    parsed.nameCount == 1,
            ) {
                "The configured entry must be one explicit .mjs basename"
            }
        }

        private fun resolveReference(fromPublicName: String, reference: ModuleReference) {
            val specifier = reference.specifier
            if (reference.kind == ReferenceKind.DynamicImport &&
                isReviewedEnvironmentDeadImport(reference, specifier)
            ) {
                return
            }
            require(
                reference.kind != ReferenceKind.DynamicImport ||
                    specifier !in REVIEWED_DEAD_DYNAMIC_IMPORTS,
            ) {
                "Unreviewed dynamic import loader shape for: $specifier"
            }

            if (specifier == "@js-joda/core") {
                require(reference.kind == ReferenceKind.StaticImport) {
                    "Unreviewed @js-joda/core loader shape: ${reference.kind}"
                }
                sawJodaImport = true
                addClasspathAsset(
                    requireNotNull(runtimeResources["js-joda.esm.js"]) {
                        "Pinned Joda runtime resource is not configured"
                    },
                )
                return
            }

            val isRelativeReference =
                specifier.startsWith("./") ||
                    specifier.startsWith("../") ||
                    (
                        reference.kind == ReferenceKind.NewUrl &&
                            !specifier.startsWith("/") &&
                            ':' !in specifier.substringBefore('/')
                        )
            require(isRelativeReference) {
                "Unreviewed absolute, network, or bare module reference: $specifier"
            }
            require('?' !in specifier && '#' !in specifier && '\\' !in specifier) {
                "Unreviewed relative module reference: $specifier"
            }
            if (specifier == "./" && reference.kind == ReferenceKind.NewUrl) {
                require(
                    fromPublicName == "skiko.mjs" &&
                        reference.reviewedLoaderContext ==
                        ReviewedLoaderContext.SkikoDirectoryUrl,
                ) {
                    "Unreviewed new URL directory loader shape"
                }
                return
            }
            require(specifier.split('/').none { it == ".." }) {
                "Module traversal outside the validated linker directory is forbidden: $specifier"
            }
            val normalizedSpelling = specifier.removePrefix("./")
            require(
                !normalizedSpelling.contains("//") &&
                    normalizedSpelling.split('/').none { it.isEmpty() || it == "." },
            ) {
                "Module reference is a duplicate normalized path alias: $specifier"
            }

            val parent = fromPublicName.substringBeforeLast('/', "")
            val normalized = Paths.get(parent).resolve(specifier).normalize()
            require(!normalized.isAbsolute && normalized.none { it.toString() == ".." }) {
                "Module reference resolves outside the validated linker directory: $specifier"
            }
            val publicName = normalized.joinToString("/")
            require(publicName.isNotBlank()) { "Module reference does not name an asset: $specifier" }
            addCodeAsset(publicName)
        }

        private fun addCodeAsset(publicName: String) {
            val route = assetRoute(publicName)
            if (route in manifest) return

            val file = linkerDirectory.resolve(publicName)
            if (Files.exists(file, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                addFilesystemAsset(publicName, file)
                return
            }

            val pinned = runtimeResources[publicName]
                ?: throw IllegalArgumentException("Referenced asset is missing: $publicName")
            addClasspathAsset(pinned)
        }

        private fun addFilesystemAsset(publicName: String, file: Path) {
            validateFilesystemEntry(file, linkerDirectory, "linker asset")
            val bytes = Files.readAllBytes(file)
            addAsset(publicName, bytes, AssetOrigin.Filesystem)
        }

        private fun addClasspathAsset(pinned: PinnedClasspathAsset) {
            val route = assetRoute(pinned.publicFileName)
            if (route in manifest) return
            require(!Files.exists(linkerDirectory.resolve(pinned.publicFileName))) {
                "Duplicate normalized public asset path: $route"
            }

            val resources = Collections.list(
                classLoader.getResources(pinned.classpathResourceName),
            )
            require(resources.size == 1) {
                "Pinned classpath resource ${pinned.classpathResourceName} resolved " +
                    "${resources.size} times; expected exactly once"
            }
            val bytes = resources.single().openStream().use { it.readBytes() }
            val actualHash = sha256(bytes)
            require(actualHash == pinned.expectedSha256) {
                "Pinned classpath resource ${pinned.classpathResourceName} has SHA-256 " +
                    "$actualHash, expected ${pinned.expectedSha256}"
            }
            val origin = if (pinned.publicFileName == "js-joda.esm.js") {
                AssetOrigin.ClasspathJoda
            } else {
                AssetOrigin.ClasspathSkiko
            }
            addAsset(pinned.publicFileName, bytes, origin)
        }

        private fun addAsset(publicName: String, bytes: ByteArray, origin: AssetOrigin) {
            val route = assetRoute(publicName)
            require(route !in manifest) { "Duplicate normalized public asset path: $route" }
            val contentType = mimeType(publicName)
            manifest[route] = WebAsset(bytes, contentType, sha256(bytes))
            origins[route] = origin
            if (publicName.endsWith(".mjs") || publicName.endsWith(".js")) {
                pendingCode.addLast(publicName)
            }
        }

        private fun addComposeResources() {
            Files.walk(composeResourcesDirectory).use { entries ->
                entries.forEach { path ->
                    if (path == composeResourcesDirectory) return@forEach
                    require(!Files.isSymbolicLink(path)) {
                        "Compose resources may not contain a symbolic link: $path"
                    }
                    if (Files.isDirectory(path, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                        validateFilesystemEntry(path, composeResourcesDirectory, "resource directory")
                        return@forEach
                    }
                    validateFilesystemEntry(path, composeResourcesDirectory, "resource asset")
                    val relative = composeResourcesDirectory.relativize(path)
                        .joinToString("/")
                    val route = "$RESOURCE_PREFIX$relative"
                    require(route !in manifest) {
                        "Duplicate normalized public asset path: $route"
                    }
                    val bytes = Files.readAllBytes(path)
                    manifest[route] = WebAsset(bytes, mimeType(relative), sha256(bytes))
                    origins[route] = AssetOrigin.ComposeResource
                }
            }
        }

        private fun validateRequiredRuntime() {
            require(sawJodaImport) {
                "The observed @js-joda/core import was not present in the module closure"
            }
            requireAssetHash("/assets/skiko.mjs", SKIKO_MJS_SHA256)
            requireAssetHash("/assets/skiko.wasm", SKIKO_WASM_SHA256)
            requireAssetHash("/assets/js-joda.esm.js", JODA_SHA256)
            requireAssetHash(GATE_MARKER_ROUTE, GATE_MARKER_SHA256)
            val applicationWasm = manifest.keys.any { route ->
                route.endsWith(".wasm") &&
                    route != "/assets/skiko.wasm" &&
                    origins[route] == AssetOrigin.Filesystem
            }
            require(applicationWasm) {
                "The validated closure does not contain an application Wasm binary"
            }
        }

        private fun requireAssetHash(route: String, expected: String) {
            val asset = manifest[route]
                ?: throw IllegalArgumentException("Required runtime asset is missing: $route")
            require(asset.sha256 == expected) {
                "Runtime asset $route has SHA-256 ${asset.sha256}, expected $expected"
            }
        }

        private fun loadAndRenderIndex(entryPath: String): String {
            val resources = Collections.list(classLoader.getResources(INDEX_RESOURCE))
            require(resources.size == 1) {
                "Authored index resource $INDEX_RESOURCE resolved ${resources.size} times; " +
                    "expected exactly once"
            }
            val template = resources.single().openStream().bufferedReader().use { it.readText() }
            require(template.windowed(ENTRY_TOKEN.length).count { it == ENTRY_TOKEN } == 1) {
                "Authored index must contain exactly one $ENTRY_TOKEN token"
            }
            val html = template.replace(ENTRY_TOKEN, entryPath)
            require(
                Regex("""<script\s+type="module"\s+src="${Regex.escape(entryPath)}"\s*></script>""")
                    .findAll(html)
                    .count() == 1,
            ) {
                "Authored index module script does not match the configured entry"
            }
            require(Regex("""<script\s+type="module"""").findAll(html).count() == 1) {
                "Authored index must contain exactly one module script"
            }
            require(Regex("""<script\s+type="importmap">""").findAll(html).count() == 1) {
                "Authored index must contain exactly one import map"
            }
            require(Regex("""<script\b""").findAll(html).count() == 2) {
                "Authored index must contain only its import map and module scripts"
            }
            val importMapBody = Regex(
                """<script\s+type="importmap">\s*(.*?)\s*</script>""",
                RegexOption.DOT_MATCHES_ALL,
            ).find(html)?.groupValues?.get(1).orEmpty()
            val compactImportMap = importMapBody.replace(Regex("""\s"""), "")
            require(
                compactImportMap ==
                    """{"imports":{"@js-joda/core":"/assets/js-joda.esm.js"}}""",
            ) {
                "Authored index import map must contain only the reviewed Joda mapping"
            }
            return html
        }

        private fun isReviewedEnvironmentDeadImport(
            reference: ModuleReference,
            specifier: String,
        ): Boolean = when (specifier) {
            "node:module" ->
                reference.reviewedLoaderContext in setOf(
                    ReviewedLoaderContext.NodeBlock,
                    ReviewedLoaderContext.NodeTernary,
                )

            "https://deno.land/std/path/mod.ts" ->
                reference.reviewedLoaderContext == ReviewedLoaderContext.DenoBlock

            "module" ->
                reference.reviewedLoaderContext == ReviewedLoaderContext.SkikoDeadBlock

            in KOTLIN_IO_NODE_DYNAMIC_IMPORTS ->
                reference.reviewedLoaderContext == ReviewedLoaderContext.KotlinIoNodeTernary

            else -> false
        }

        private fun assetRoute(publicName: String): String = "/assets/$publicName"

        companion object {
            private val KOTLIN_IO_NODE_DYNAMIC_IMPORTS = setOf(
                "node:buffer",
                "node:os",
                "node:path",
                "node:fs",
            )

            private val REVIEWED_DEAD_DYNAMIC_IMPORTS = setOf(
                "node:module",
                "https://deno.land/std/path/mod.ts",
                "module",
            ) + KOTLIN_IO_NODE_DYNAMIC_IMPORTS
        }
    }
}

internal fun productionWebRuntimeResources(): List<PinnedClasspathAsset> = listOf(
    PinnedClasspathAsset(
        publicFileName = "skiko.mjs",
        classpathResourceName = "skiko.mjs",
        expectedSha256 =
            "7fa5652ceb6343affed0360d2a8e5e35dbce1dff6192b2268c7519861af2dff4",
    ),
    PinnedClasspathAsset(
        publicFileName = "skiko.wasm",
        classpathResourceName = "skiko.wasm",
        expectedSha256 =
            "46caff5f783599bd1c5d3e5e87959d7cb5102c515aac671c9280664368e71dab",
    ),
    PinnedClasspathAsset(
        publicFileName = "js-joda.esm.js",
        classpathResourceName =
            "META-INF/resources/webjars/js-joda__core/3.2.0/dist/js-joda.esm.js",
        expectedSha256 =
            "a716a37f4c3bb47f8795688e1cd6451130a08d825d8a6df664ef72b349ec445b",
    ),
)

private fun List<PinnedClasspathAsset>.associateUniqueByPublicName():
    Map<String, PinnedClasspathAsset> {
    val result = linkedMapOf<String, PinnedClasspathAsset>()
    forEach { asset ->
        require(
            asset.publicFileName.isNotBlank() &&
                Paths.get(asset.publicFileName).nameCount == 1 &&
                Paths.get(asset.publicFileName).fileName.toString() == asset.publicFileName,
        ) {
            "Pinned classpath public filename must be one normalized basename"
        }
        require(result.put(asset.publicFileName, asset) == null) {
            "Pinned classpath manifest has a duplicate normalized public path: " +
                asset.publicFileName
        }
    }
    return result
}

private fun requireCanonicalDirectory(
    candidate: Path,
    label: String,
    projectRoot: Path? = null,
): Path {
    require(candidate.isAbsolute) { "$label must be absolute and canonical: $candidate" }
    val normalized = candidate.toAbsolutePath().normalize()
    require(normalized == candidate) { "$label must be canonical: $candidate" }
    require(!Files.isSymbolicLink(candidate)) { "$label may not be a symbolic link: $candidate" }
    val real = runCatching { candidate.toRealPath() }.getOrElse {
        throw IllegalArgumentException("$label does not exist: $candidate", it)
    }
    require(real == candidate) { "$label must be canonical and contain no symbolic-link path: $candidate" }
    require(real.isDirectory()) { "$label must be a directory: $candidate" }
    if (projectRoot != null) {
        require(real.startsWith(projectRoot)) {
            "$label is outside the configured project root: $candidate"
        }
    }
    return real
}

private fun validateFilesystemEntry(path: Path, root: Path, label: String) {
    require(!Files.isSymbolicLink(path)) { "$label may not be a symbolic link: $path" }
    val normalized = path.toAbsolutePath().normalize()
    require(normalized.startsWith(root)) { "$label is outside the configured root: $path" }
    val real = runCatching { path.toRealPath() }.getOrElse {
        throw IllegalArgumentException("$label is missing: $path", it)
    }
    require(real == normalized && real.startsWith(root)) {
        "$label resolves outside the configured root or through a symbolic link: $path"
    }
    require(real.isRegularFile() || real.isDirectory()) {
        "$label must be a regular file or directory: $path"
    }
}

private fun mimeType(publicName: String): String = when (publicName.substringAfterLast('.', "")) {
    "mjs", "js" -> "text/javascript"
    "wasm" -> "application/wasm"
    "css" -> "text/css"
    "json" -> "application/json"
    "txt", "text" -> "text/plain"
    "svg" -> "image/svg+xml"
    "png" -> "image/png"
    "jpg", "jpeg" -> "image/jpeg"
    "gif" -> "image/gif"
    "webp" -> "image/webp"
    "ico" -> "image/x-icon"
    "woff" -> "font/woff"
    "woff2" -> "font/woff2"
    "ttf" -> "font/ttf"
    "otf" -> "font/otf"
    else -> throw IllegalArgumentException(
        "Observed runtime asset extension has no reviewed MIME mapping: $publicName",
    )
}

private fun sha256(bytes: ByteArray): String =
    MessageDigest.getInstance("SHA-256")
        .digest(bytes)
        .joinToString("") { "%02x".format(it) }

private enum class AssetOrigin {
    Filesystem,
    ClasspathSkiko,
    ClasspathJoda,
    ComposeResource,
}

private enum class ReferenceKind {
    StaticImport,
    DynamicImport,
    ExportFrom,
    NewUrl,
}

private data class ModuleReference(
    val kind: ReferenceKind,
    val specifier: String,
    val reviewedLoaderContext: ReviewedLoaderContext?,
)

private enum class ReviewedLoaderContext {
    NodeBlock,
    NodeTernary,
    KotlinIoNodeTernary,
    DenoBlock,
    SkikoDeadBlock,
    SkikoDirectoryUrl,
}

private enum class NamedEnvironmentPredicate {
    Node,
    Deno,
}

private class ModuleReferenceScanner(private val source: String) {
    private val tokens = tokenize(source)

    fun references(): List<ModuleReference> {
        val references = mutableListOf<ModuleReference>()
        var index = 0
        while (index < tokens.size) {
            val token = tokens[index]
            if (token is JsToken.Identifier) {
                when (token.value) {
                    "import" -> scanImport(index)?.let(references::add)
                    "export" -> scanExport(index)?.let(references::add)
                    "new" -> scanNewUrl(index)?.let(references::add)
                }
            }
            index++
        }
        return references
    }

    private fun scanImport(index: Int): ModuleReference? {
        val import = tokens[index]
        val next = tokens.getOrNull(index + 1)
        if (next is JsToken.Punctuation && next.value == ".") return null
        if (next is JsToken.Punctuation && next.value == "(") {
            val value = tokens.getOrNull(index + 2)
            require(value is JsToken.StringLiteral) {
                "Found an unreviewed non-literal dynamic import"
            }
            require((tokens.getOrNull(index + 3) as? JsToken.Punctuation)?.value == ")") {
                "Found an unreviewed dynamic import loader shape"
            }
            return reference(
                kind = ReferenceKind.DynamicImport,
                specifier = value.value,
                reviewedLoaderContext = reviewedDynamicImportContext(index),
            )
        }
        if (next is JsToken.StringLiteral) {
            return reference(ReferenceKind.StaticImport, next.value)
        }
        val fromIndex = findAhead(index + 1) { candidate ->
            candidate is JsToken.Identifier && candidate.value == "from"
        } ?: throw IllegalArgumentException("Found an unreviewed static import loader shape")
        val value = tokens.getOrNull(fromIndex + 1)
        require(value is JsToken.StringLiteral) {
            "Found an unreviewed static import loader shape"
        }
        return reference(ReferenceKind.StaticImport, value.value)
    }

    private fun scanExport(index: Int): ModuleReference? {
        val next = tokens.getOrNull(index + 1)
        if (next is JsToken.Identifier &&
            next.value in setOf("const", "let", "var", "function", "class", "default")
        ) {
            return null
        }
        if (next !is JsToken.Punctuation || next.value !in setOf("*", "{")) return null
        val fromIndex = findAhead(index + 1) { candidate ->
            candidate is JsToken.Identifier && candidate.value == "from"
        } ?: return null
        val value = tokens.getOrNull(fromIndex + 1)
        require(value is JsToken.StringLiteral) {
            "Found an unreviewed export-from loader shape"
        }
        return reference(ReferenceKind.ExportFrom, value.value)
    }

    private fun scanNewUrl(index: Int): ModuleReference? {
        val url = tokens.getOrNull(index + 1) as? JsToken.Identifier ?: return null
        if (url.value != "URL") return null
        val open = tokens.getOrNull(index + 2) as? JsToken.Punctuation ?: return null
        if (open.value != "(") return null
        var nestingDepth = 0
        var commaIndex: Int? = null
        var cursor = index + 3
        while (cursor < tokens.size) {
            val candidate = tokens[cursor]
            if (candidate is JsToken.Punctuation) {
                when (candidate.value) {
                    "(", "[", "{" -> nestingDepth++
                    ")", "]", "}" -> {
                        if (nestingDepth == 0) break
                        nestingDepth--
                    }

                    "," -> if (nestingDepth == 0) {
                        commaIndex = cursor
                        break
                    }
                }
            }
            cursor++
        }
        val separator = commaIndex ?: return null
        val hasImportMetaUrl =
            (tokens.getOrNull(separator + 1) as? JsToken.Identifier)?.value == "import" &&
                (tokens.getOrNull(separator + 2) as? JsToken.Punctuation)?.value == "." &&
                (tokens.getOrNull(separator + 3) as? JsToken.Identifier)?.value == "meta" &&
                (tokens.getOrNull(separator + 4) as? JsToken.Punctuation)?.value == "." &&
                (tokens.getOrNull(separator + 5) as? JsToken.Identifier)?.value == "url"
        if (!hasImportMetaUrl) return null
        val firstArgumentTokens = tokens.subList(index + 3, separator)
        require(
            firstArgumentTokens.size == 1 &&
                firstArgumentTokens.single() is JsToken.StringLiteral,
        ) {
            "Found an unreviewed non-literal new URL asset reference"
        }
        val firstArgument = firstArgumentTokens.single() as JsToken.StringLiteral
        val loaderContext = if (matchesBefore(index, SKIKO_DIRECTORY_URL_PREFIX)) {
            ReviewedLoaderContext.SkikoDirectoryUrl
        } else {
            null
        }
        return reference(ReferenceKind.NewUrl, firstArgument.value, loaderContext)
    }

    private fun findAhead(start: Int, predicate: (JsToken) -> Boolean): Int? {
        for (candidateIndex in start until minOf(tokens.size, start + 100)) {
            val candidate = tokens[candidateIndex]
            if (candidate is JsToken.Punctuation && candidate.value == ";") return null
            if (predicate(candidate)) return candidateIndex
        }
        return null
    }

    private fun reference(
        kind: ReferenceKind,
        specifier: String,
        reviewedLoaderContext: ReviewedLoaderContext? = null,
    ): ModuleReference = ModuleReference(
        kind = kind,
        specifier = specifier,
        reviewedLoaderContext = reviewedLoaderContext,
    )

    private fun reviewedDynamicImportContext(index: Int): ReviewedLoaderContext? {
        val blockOpen = enclosingBlockOpen(index)
        if (blockOpen != null) {
            val blockPrefix = tokens.subList(blockOpen + 1, index)
            if (blockPrefix.matchesExactly(NODE_BLOCK_BODY_PREFIX)) {
                if (
                    (
                        matchesBefore(blockOpen, NODE_NAMED_IF_PREFIX) &&
                            isReviewedNamedPredicateUse(
                                NamedEnvironmentPredicate.Node,
                                blockOpen,
                            )
                        ) ||
                    matchesBefore(blockOpen, NODE_DIRECT_IF_PREFIX)
                ) {
                    return ReviewedLoaderContext.NodeBlock
                }
            }
            if (blockPrefix.matchesExactly(DENO_BLOCK_BODY_PREFIX) &&
                matchesBefore(blockOpen, DENO_IF_PREFIX) &&
                isReviewedNamedPredicateUse(NamedEnvironmentPredicate.Deno, blockOpen)
            ) {
                return ReviewedLoaderContext.DenoBlock
            }
            if (blockPrefix.matchesExactly(SKIKO_DEAD_BLOCK_BODY_PREFIX) &&
                matchesBefore(blockOpen, SKIKO_DEAD_IF_PREFIX)
            ) {
                return ReviewedLoaderContext.SkikoDeadBlock
            }
        }
        return if (matchesBefore(index, NODE_TERNARY_PREFIX)) {
            ReviewedLoaderContext.NodeTernary
        } else if (matchesBefore(index, KOTLIN_IO_NODE_TERNARY_PREFIX)) {
            ReviewedLoaderContext.KotlinIoNodeTernary
        } else {
            null
        }
    }

    private fun enclosingBlockOpen(index: Int): Int? {
        var depth = 0
        for (candidateIndex in index - 1 downTo 0) {
            when (val candidate = tokens[candidateIndex]) {
                is JsToken.TemplateBoundary -> if (candidate.opening) return null
                is JsToken.Punctuation -> when (candidate.value) {
                    "}" -> depth++
                    "{" -> if (depth == 0) return candidateIndex else depth--
                }

                else -> Unit
            }
        }
        return null
    }

    private fun isReviewedNamedPredicateUse(
        predicate: NamedEnvironmentPredicate,
        useIndex: Int,
    ): Boolean {
        val nodeDeclaration = uniqueCanonicalNodeDeclaration() ?: return false
        if (!isUnchangedBinding("isNodeJs", nodeDeclaration + 1)) return false
        if (nodeDeclaration >= useIndex || hasAmbiguousSlashBefore(useIndex)) return false
        if (predicate == NamedEnvironmentPredicate.Node) return true

        val denoDeclaration = uniqueCanonicalDenoDeclaration() ?: return false
        return denoDeclaration < useIndex &&
            isUnchangedBinding("isDeno", denoDeclaration + 1)
    }

    private fun uniqueCanonicalNodeDeclaration(): Int? =
        uniqueModuleLevelMatch { start ->
            matchesAt(start, NODE_DECLARATION) &&
                matchesAt(start + NODE_DECLARATION.size, DENO_DECLARATION)
        }

    private fun uniqueCanonicalDenoDeclaration(): Int? =
        uniqueModuleLevelMatch { start ->
            if (!matchesAt(start, DENO_DECLARATION)) return@uniqueModuleLevelMatch false
            val follower = start + DENO_DECLARATION.size
            matchesAt(follower, GENERATED_DENO_FOLLOWER)
        }

    private fun uniqueModuleLevelMatch(predicate: (Int) -> Boolean): Int? {
        var match: Int? = null
        for (index in tokens.indices) {
            if (!isModuleLevel(index) || !predicate(index)) continue
            if (match != null) return null
            match = index
        }
        return match
    }

    private fun isModuleLevel(index: Int): Boolean {
        var braceDepth = 0
        var templateDepth = 0
        for (candidate in tokens.subList(0, index)) {
            when (candidate) {
                is JsToken.TemplateBoundary -> {
                    templateDepth += if (candidate.opening) 1 else -1
                }

                is JsToken.Punctuation -> if (templateDepth == 0) {
                    when (candidate.value) {
                        "{" -> braceDepth++
                        "}" -> braceDepth--
                    }
                }

                else -> Unit
            }
        }
        return braceDepth == 0 && templateDepth == 0
    }

    private fun isUnchangedBinding(
        name: String,
        canonicalNameIndex: Int,
    ): Boolean = tokens.indices.none { index ->
        index != canonicalNameIndex &&
            (tokens[index] as? JsToken.Identifier)?.value == name &&
            (
                isBindingDeclaration(index) ||
                    isFunctionParameter(index) ||
                    isAssignmentOrUpdate(index)
                )
    }

    private fun isBindingDeclaration(index: Int): Boolean {
        val previous = tokens.getOrNull(index - 1)
        if (previous is JsToken.Identifier &&
            previous.value in setOf("const", "let", "var", "function", "class", "import")
        ) {
            return true
        }
        if (previous !is JsToken.Punctuation ||
            previous.value !in setOf("{", "[", ":", ",")
        ) {
            return false
        }
        for (candidateIndex in index - 2 downTo maxOf(0, index - 64)) {
            when (val candidate = tokens[candidateIndex]) {
                is JsToken.Identifier ->
                    if (candidate.value in setOf("const", "let", "var", "import")) return true

                is JsToken.Punctuation ->
                    if (candidate.value in setOf("=", ";", ")")) return false

                is JsToken.TemplateBoundary -> return false
                else -> Unit
            }
        }
        return false
    }

    private fun isFunctionParameter(index: Int): Boolean {
        if (matchesAt(index + 1, listOf(punctuation("="), punctuation(">")))) {
            return true
        }
        val open = enclosingParenthesisOpen(index) ?: return false
        val close = matchingParenthesisClose(open) ?: return false
        val beforeOpen = tokens.getOrNull(open - 1)
        val beforeBeforeOpen = tokens.getOrNull(open - 2)
        if (beforeOpen is JsToken.Identifier &&
            beforeOpen.value in setOf("function", "catch")
        ) {
            return true
        }
        if (beforeOpen is JsToken.Identifier &&
            beforeBeforeOpen is JsToken.Identifier &&
            beforeBeforeOpen.value == "function"
        ) {
            return true
        }
        if (matchesAt(close + 1, listOf(punctuation("="), punctuation(">")))) {
            return true
        }
        val followsWithBody =
            (tokens.getOrNull(close + 1) as? JsToken.Punctuation)?.value == "{"
        val isControlCondition =
            beforeOpen is JsToken.Identifier &&
                beforeOpen.value in setOf("if", "for", "while", "switch", "with")
        return followsWithBody && beforeOpen is JsToken.Identifier && !isControlCondition
    }

    private fun enclosingParenthesisOpen(index: Int): Int? {
        var depth = 0
        for (candidateIndex in index - 1 downTo 0) {
            when (val candidate = tokens[candidateIndex]) {
                is JsToken.TemplateBoundary -> if (candidate.opening) return null
                is JsToken.Punctuation -> when (candidate.value) {
                    ")" -> depth++
                    "(" -> if (depth == 0) return candidateIndex else depth--
                }

                else -> Unit
            }
        }
        return null
    }

    private fun matchingParenthesisClose(open: Int): Int? {
        var depth = 0
        for (candidateIndex in open + 1 until tokens.size) {
            when (val candidate = tokens[candidateIndex]) {
                is JsToken.TemplateBoundary -> if (!candidate.opening) return null
                is JsToken.Punctuation -> when (candidate.value) {
                    "(" -> depth++
                    ")" -> if (depth == 0) return candidateIndex else depth--
                }

                else -> Unit
            }
        }
        return null
    }

    private fun isAssignmentOrUpdate(index: Int): Boolean {
        val next = (tokens.getOrNull(index + 1) as? JsToken.Punctuation)?.value
        val nextTwo = (tokens.getOrNull(index + 2) as? JsToken.Punctuation)?.value
        val nextThree = (tokens.getOrNull(index + 3) as? JsToken.Punctuation)?.value
        if (next == "=" && nextTwo != "=") return true
        if (next in setOf("+", "-") && nextTwo == next) return true
        if (next in setOf("+", "-", "*", "/", "%", "&", "|", "^", "?") &&
            (nextTwo == "=" || nextThree == "=")
        ) {
            return true
        }
        val previous = (tokens.getOrNull(index - 1) as? JsToken.Punctuation)?.value
        val previousTwo = (tokens.getOrNull(index - 2) as? JsToken.Punctuation)?.value
        return previous in setOf("+", "-") && previousTwo == previous
    }

    private fun hasAmbiguousSlashBefore(useIndex: Int): Boolean =
        tokens.subList(0, useIndex).any { token ->
            token is JsToken.Punctuation && token.value == "/"
        }

    private fun matchesBefore(
        endExclusive: Int,
        expected: List<JsTokenShape>,
    ): Boolean {
        val start = endExclusive - expected.size
        if (start < 0) return false
        return tokens.subList(start, endExclusive).matchesExactly(expected)
    }

    private fun matchesAt(
        start: Int,
        expected: List<JsTokenShape>,
    ): Boolean {
        if (start < 0 || start + expected.size > tokens.size) return false
        return tokens.subList(start, start + expected.size).matchesExactly(expected)
    }

    companion object {
        private val NODE_DECLARATION = listOf(
            identifier("const"),
            identifier("isNodeJs"),
            punctuation("="),
            punctuation("("),
            identifier("typeof"),
            identifier("process"),
            punctuation("!"),
            punctuation("="),
            punctuation("="),
            stringLiteral("undefined"),
            punctuation(")"),
            punctuation("&"),
            punctuation("&"),
            punctuation("("),
            identifier("process"),
            punctuation("."),
            identifier("release"),
            punctuation("."),
            identifier("name"),
            punctuation("="),
            punctuation("="),
            punctuation("="),
            stringLiteral("node"),
            punctuation(")"),
            punctuation(";"),
        )
        private val DENO_DECLARATION = listOf(
            identifier("const"),
            identifier("isDeno"),
            punctuation("="),
            punctuation("!"),
            identifier("isNodeJs"),
            punctuation("&"),
            punctuation("&"),
            punctuation("("),
            identifier("typeof"),
            identifier("Deno"),
            punctuation("!"),
            punctuation("="),
            punctuation("="),
            stringLiteral("undefined"),
            punctuation(")"),
        )
        private val GENERATED_DENO_FOLLOWER = listOf(
            identifier("const"),
            identifier("isStandaloneJsVM"),
            punctuation("="),
        )
        private val NODE_NAMED_IF_PREFIX = listOf(
            identifier("if"),
            punctuation("("),
            identifier("isNodeJs"),
            punctuation(")"),
        )
        private val NODE_DIRECT_IF_PREFIX = listOf(
            identifier("if"),
            punctuation("("),
            identifier("typeof"),
            identifier("process"),
            punctuation("!"),
            punctuation("="),
            punctuation("="),
            stringLiteral("undefined"),
            punctuation("&"),
            punctuation("&"),
            identifier("process"),
            punctuation("."),
            identifier("release"),
            punctuation("."),
            identifier("name"),
            punctuation("="),
            punctuation("="),
            punctuation("="),
            stringLiteral("node"),
            punctuation(")"),
        )
        private val NODE_BLOCK_BODY_PREFIX = listOf(
            identifier("const"),
            identifier("module"),
            punctuation("="),
            identifier("await"),
        )
        private val DENO_IF_PREFIX = listOf(
            identifier("if"),
            punctuation("("),
            identifier("isDeno"),
            punctuation(")"),
        )
        private val DENO_BLOCK_BODY_PREFIX = listOf(
            identifier("const"),
            identifier("path"),
            punctuation("="),
            identifier("await"),
        )
        private val SKIKO_DEAD_IF_PREFIX = listOf(
            identifier("if"),
            punctuation("("),
            identifier("false"),
            punctuation(")"),
        )
        private val SKIKO_DEAD_BLOCK_BODY_PREFIX = listOf(
            identifier("const"),
            punctuation("{"),
            identifier("createRequire"),
            punctuation("}"),
            punctuation("="),
            identifier("await"),
        )
        private val NODE_TERNARY_PREFIX = listOf(
            identifier("globalThis"),
            punctuation("."),
            identifier("module"),
            punctuation("="),
            punctuation("("),
            identifier("typeof"),
            identifier("process"),
            punctuation("!"),
            punctuation("="),
            punctuation("="),
            stringLiteral("undefined"),
            punctuation(")"),
            punctuation("&"),
            punctuation("&"),
            punctuation("("),
            identifier("process"),
            punctuation("."),
            identifier("release"),
            punctuation("."),
            identifier("name"),
            punctuation("="),
            punctuation("="),
            punctuation("="),
            stringLiteral("node"),
            punctuation(")"),
            punctuation("?"),
            identifier("await"),
        )
        private val KOTLIN_IO_NODE_TERNARY_PREFIX = listOf(
            punctuation("("),
            punctuation("("),
            identifier("module"),
            punctuation(")"),
            punctuation("="),
            punctuation(">"),
            punctuation("("),
            punctuation(")"),
            punctuation("="),
            punctuation(">"),
            identifier("module"),
            punctuation(")"),
            punctuation("("),
            punctuation("("),
            punctuation("("),
            identifier("typeof"),
            identifier("process"),
            punctuation("!"),
            punctuation("="),
            punctuation("="),
            stringLiteral("undefined"),
            punctuation(")"),
            punctuation("&"),
            punctuation("&"),
            punctuation("("),
            identifier("process"),
            punctuation("."),
            identifier("release"),
            punctuation("."),
            identifier("name"),
            punctuation("="),
            punctuation("="),
            punctuation("="),
            stringLiteral("node"),
            punctuation(")"),
            punctuation(")"),
            punctuation("?"),
            identifier("await"),
        )
        private val SKIKO_DIRECTORY_URL_PREFIX = listOf(
            identifier("scriptDirectory"),
            punctuation("="),
            identifier("require"),
            punctuation("("),
            stringLiteral("url"),
            punctuation(")"),
            punctuation("."),
            identifier("fileURLToPath"),
            punctuation("("),
        )
    }
}

private sealed interface JsToken {
    val start: Int

    data class Identifier(val value: String, override val start: Int) : JsToken

    data class StringLiteral(val value: String, override val start: Int) : JsToken

    data class RegexLiteral(override val start: Int) : JsToken

    data class Punctuation(val value: String, override val start: Int) : JsToken

    data class TemplateBoundary(
        val opening: Boolean,
        override val start: Int,
    ) : JsToken
}

private sealed interface JsTokenShape {
    val value: String

    data class Identifier(override val value: String) : JsTokenShape

    data class StringLiteral(override val value: String) : JsTokenShape

    data class Punctuation(override val value: String) : JsTokenShape
}

private fun identifier(value: String): JsTokenShape = JsTokenShape.Identifier(value)

private fun stringLiteral(value: String): JsTokenShape = JsTokenShape.StringLiteral(value)

private fun punctuation(value: String): JsTokenShape = JsTokenShape.Punctuation(value)

private fun List<JsToken>.matchesExactly(expected: List<JsTokenShape>): Boolean =
    size == expected.size && indices.all { index ->
        when (val token = this[index]) {
            is JsToken.Identifier ->
                expected[index] == JsTokenShape.Identifier(token.value)

            is JsToken.StringLiteral ->
                expected[index] == JsTokenShape.StringLiteral(token.value)

            is JsToken.RegexLiteral -> false

            is JsToken.Punctuation ->
                expected[index] == JsTokenShape.Punctuation(token.value)

            is JsToken.TemplateBoundary -> false
        }
    }

private fun tokenize(source: String): List<JsToken> = JsTokenizer(source).tokenize()

private class JsTokenizer(private val source: String) {
    private val tokens = mutableListOf<JsToken>()
    private var index = 0

    fun tokenize(): List<JsToken> {
        scanCode(inTemplateSubstitution = false)
        return tokens
    }

    private fun scanCode(inTemplateSubstitution: Boolean) {
        var braceDepth = 0
        while (index < source.length) {
            val character = source[index]
            when {
                character.isWhitespace() -> index++
                character == '/' && source.getOrNull(index + 1) == '/' -> scanLineComment()
                character == '/' && source.getOrNull(index + 1) == '*' -> scanBlockComment()
                character == '/' && canStartRegexLiteral() -> scanRegexLiteral()
                character == '/' && inTemplateSubstitution ->
                    throw IllegalArgumentException(
                        "Unreviewed slash syntax inside JavaScript template substitution",
                    )

                character == '\'' || character == '"' -> scanString()
                character == '`' -> scanTemplate()
                character == '{' -> {
                    tokens += JsToken.Punctuation(character.toString(), index)
                    braceDepth++
                    index++
                }

                character == '}' && inTemplateSubstitution && braceDepth == 0 -> {
                    tokens += JsToken.TemplateBoundary(opening = false, start = index)
                    index++
                    return
                }

                character == '}' -> {
                    tokens += JsToken.Punctuation(character.toString(), index)
                    braceDepth--
                    index++
                }

                character.isLetter() || character == '_' || character == '$' ->
                    scanIdentifier()

                else -> {
                    tokens += JsToken.Punctuation(character.toString(), index)
                    index++
                }
            }
        }
        require(!inTemplateSubstitution) {
            "Unterminated JavaScript template substitution"
        }
    }

    private fun scanLineComment() {
        index += 2
        while (index < source.length && source[index] != '\n') index++
    }

    private fun scanBlockComment() {
        val end = source.indexOf("*/", index + 2)
        require(end >= 0) { "Unterminated JavaScript block comment" }
        index = end + 2
    }

    private fun canStartRegexLiteral(): Boolean = when (val previous = tokens.lastOrNull()) {
        null -> true
        is JsToken.Punctuation -> previous.value in REGEX_EXPRESSION_PREFIXES
        is JsToken.Identifier -> previous.value in REGEX_EXPRESSION_KEYWORDS
        else -> false
    }

    private fun scanRegexLiteral() {
        val start = index++
        var inCharacterClass = false
        while (index < source.length) {
            when (source[index]) {
                '\\' -> {
                    require(index + 1 < source.length) { "Unterminated JavaScript regex escape" }
                    index += 2
                }

                '[' -> {
                    inCharacterClass = true
                    index++
                }

                ']' -> {
                    inCharacterClass = false
                    index++
                }

                '/' -> if (!inCharacterClass) {
                    index++
                    while (index < source.length && source[index].isLetter()) index++
                    tokens += JsToken.RegexLiteral(start)
                    return
                } else {
                    index++
                }

                '\n', '\r' -> throw IllegalArgumentException("Unterminated JavaScript regex literal")
                else -> index++
            }
        }
        throw IllegalArgumentException("Unterminated JavaScript regex literal")
    }

    private fun scanString() {
        val start = index
        val quote = source[index]
        index++
        val value = StringBuilder()
        while (index < source.length && source[index] != quote) {
            require(source[index] != '\n' && source[index] != '\r') {
                "Unterminated JavaScript string literal"
            }
            if (source[index] == '\\') {
                require(index + 1 < source.length) {
                    "Unterminated JavaScript string escape"
                }
                value.append(source[index + 1])
                index += 2
            } else {
                value.append(source[index])
                index++
            }
        }
        require(index < source.length) { "Unterminated JavaScript string literal" }
        index++
        tokens += JsToken.StringLiteral(value.toString(), start)
    }

    private fun scanTemplate() {
        index++
        while (index < source.length) {
            when {
                source[index] == '\\' -> {
                    require(index + 1 < source.length) {
                        "Unterminated JavaScript template escape"
                    }
                    index += 2
                }

                source[index] == '`' -> {
                    index++
                    return
                }

                source[index] == '$' && source.getOrNull(index + 1) == '{' -> {
                    tokens += JsToken.TemplateBoundary(opening = true, start = index)
                    index += 2
                    scanCode(inTemplateSubstitution = true)
                }

                else -> index++
            }
        }
        throw IllegalArgumentException("Unterminated JavaScript template literal")
    }

    private fun scanIdentifier() {
        val start = index
        index++
        while (index < source.length &&
            (source[index].isLetterOrDigit() || source[index] == '_' || source[index] == '$')
        ) {
            index++
        }
        tokens += JsToken.Identifier(source.substring(start, index), start)
    }

    private companion object {
        val REGEX_EXPRESSION_PREFIXES = setOf(
            "(", "[", "{", "=", ":", ",", ";", "!", "?", "&", "|", "+", "-", "*", "/", "%", "~", "^", "<", ">",
        )
        val REGEX_EXPRESSION_KEYWORDS = setOf(
            "return", "throw", "case", "delete", "void", "typeof", "new", "in", "of", "yield", "await", "else", "do",
        )
    }
}

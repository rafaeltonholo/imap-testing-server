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

private const val KOTLIN_IO_IMPORT_OBJECT_PUBLIC_NAME =
    "dashboard-web.import-object.mjs"

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
        private const val INDEX_SHA256 =
            "3c995859793d7802f431f523ebbefdb65545309e61eabee5868abb8d1d0d7f55"
        private const val ENTRY_TOKEN = "{{DASHBOARD_WEB_ENTRY}}"
        private const val BOOTSTRAP_PUBLIC_NAME = "browser-bootstrap.js"
        private const val BOOTSTRAP_RESOURCE = "web/browser-bootstrap.js"
        private const val BOOTSTRAP_SHA256 =
            "983b4c0c576a6c4dd6bdd74209aacc2180271a1ac8b1a1dd39f30cf0b644b55c"
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
            addClasspathAsset(
                requireNotNull(runtimeResources[BOOTSTRAP_PUBLIC_NAME]) {
                    "Pinned browser bootstrap resource is not configured"
                },
            )

            while (pendingCode.isNotEmpty()) {
                val publicName = pendingCode.removeFirst()
                if (!parsedCode.add(publicName)) continue
                val asset = manifest.getValue(assetRoute(publicName))
                ModuleReferenceScanner(
                    source = asset.bytes.decodeToString(),
                    publicName = publicName,
                ).references().forEach { reference ->
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
            require(
                Regex("""[A-Za-z0-9][A-Za-z0-9._-]*\.mjs""").matches(entryFileName),
            ) {
                "The configured entry must be one ASCII-safe .mjs basename"
            }
        }

        private fun resolveReference(fromPublicName: String, reference: ModuleReference) {
            val specifier = reference.specifier
            if (reference.kind == ReferenceKind.DynamicImport &&
                isReviewedEnvironmentDeadImport(fromPublicName, reference, specifier)
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
            val origin = when (pinned.publicFileName) {
                "js-joda.esm.js" -> AssetOrigin.ClasspathJoda
                BOOTSTRAP_PUBLIC_NAME -> {
                    require(
                        pinned.classpathResourceName == BOOTSTRAP_RESOURCE &&
                            pinned.expectedSha256 == BOOTSTRAP_SHA256,
                    ) {
                        "Browser bootstrap runtime pin does not match the authored bootstrap"
                    }
                    AssetOrigin.ClasspathBootstrap
                }
                else -> AssetOrigin.ClasspathSkiko
            }
            addAsset(pinned.publicFileName, bytes, origin)
        }

        private fun addAsset(publicName: String, bytes: ByteArray, origin: AssetOrigin) {
            val route = assetRoute(publicName)
            require(route !in manifest) { "Duplicate normalized public asset path: $route" }
            val contentType = mimeType(publicName)
            manifest[route] = WebAsset(bytes, contentType, sha256(bytes))
            origins[route] = origin
            if (
                origin != AssetOrigin.ClasspathBootstrap &&
                (publicName.endsWith(".mjs") || publicName.endsWith(".js"))
            ) {
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
            requireAssetHash("/assets/$BOOTSTRAP_PUBLIC_NAME", BOOTSTRAP_SHA256)
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
            val templateBytes = resources.single().openStream().use { it.readBytes() }
            val actualHash = sha256(templateBytes)
            require(actualHash == INDEX_SHA256) {
                "Authored index resource $INDEX_RESOURCE has SHA-256 $actualHash, " +
                    "expected $INDEX_SHA256"
            }
            val template = templateBytes.decodeToString()
            require(template.windowed(ENTRY_TOKEN.length).count { it == ENTRY_TOKEN } == 1) {
                "Authored index must contain exactly one $ENTRY_TOKEN token"
            }
            val html = template.replace(ENTRY_TOKEN, entryPath)
            val bootstrapTag =
                "<script src=\"/assets/$BOOTSTRAP_PUBLIC_NAME\" " +
                    "data-dashboard-entry=\"$entryPath\"></script>"
            require(
                html.windowed(bootstrapTag.length).count { it == bootstrapTag } == 1,
            ) {
                "Authored index bootstrap script does not match the configured entry"
            }
            require(Regex("""<script\s+type="module"""").findAll(html).count() == 0) {
                "Authored index may not contain an unconditional module script"
            }
            require(Regex("""<script\s+type="importmap">""").findAll(html).count() == 1) {
                "Authored index must contain exactly one import map"
            }
            require(Regex("""<script\b""").findAll(html).count() == 2) {
                "Authored index must contain only its import map and bootstrap scripts"
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
            val importMapEnd = html.indexOf("</script>", html.indexOf("<script type=\"importmap\">"))
            require(importMapEnd >= 0 && html.indexOf(bootstrapTag) > importMapEnd) {
                "Authored index bootstrap must follow the reviewed import map"
            }
            return html
        }

        private fun isReviewedEnvironmentDeadImport(
            fromPublicName: String,
            reference: ModuleReference,
            specifier: String,
        ): Boolean = when (specifier) {
            "node:module" ->
                reference.reviewedLoaderContext == ReviewedLoaderContext.NodeBlock

            "https://deno.land/std/path/mod.ts" ->
                reference.reviewedLoaderContext == ReviewedLoaderContext.DenoBlock

            "module" ->
                reference.reviewedLoaderContext == ReviewedLoaderContext.SkikoDeadBlock

            in KOTLIN_IO_NODE_DYNAMIC_IMPORTS ->
                fromPublicName == KOTLIN_IO_IMPORT_OBJECT_PUBLIC_NAME &&
                    origins[assetRoute(fromPublicName)] == AssetOrigin.Filesystem &&
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
        publicFileName = "browser-bootstrap.js",
        classpathResourceName = "web/browser-bootstrap.js",
        expectedSha256 =
            "983b4c0c576a6c4dd6bdd74209aacc2180271a1ac8b1a1dd39f30cf0b644b55c",
    ),
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
    ClasspathBootstrap,
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
    KotlinIoNodeTernary,
    DenoBlock,
    SkikoDeadBlock,
    SkikoDirectoryUrl,
}

private enum class NamedEnvironmentPredicate {
    Node,
    Deno,
}

private class ModuleReferenceScanner(
    private val source: String,
    private val publicName: String?,
) {
    constructor(source: String) : this(source, null)

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
                reviewedLoaderContext = reviewedDynamicImportContext(index, value.value),
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
        val hasExactImportMetaUrlBase =
            (tokens.getOrNull(separator + 1) as? JsToken.Identifier)?.value == "import" &&
                (tokens.getOrNull(separator + 2) as? JsToken.Punctuation)?.value == "." &&
                (tokens.getOrNull(separator + 3) as? JsToken.Identifier)?.value == "meta" &&
                (tokens.getOrNull(separator + 4) as? JsToken.Punctuation)?.value == "." &&
                (tokens.getOrNull(separator + 5) as? JsToken.Identifier)?.value == "url" &&
                (tokens.getOrNull(separator + 6) as? JsToken.Punctuation)?.value == ")"
        require(hasExactImportMetaUrlBase) {
            "Found an unreviewed new URL base loader shape"
        }
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

    private fun reviewedDynamicImportContext(
        index: Int,
        specifier: String,
    ): ReviewedLoaderContext? {
        val blockOpen = enclosingBlockOpen(index)
        if (blockOpen != null) {
            val blockPrefix = tokens.subList(blockOpen + 1, index)
            if (blockPrefix.matchesExactly(NODE_BLOCK_BODY_PREFIX)) {
                if (
                    (
                        matchesBareIfBefore(blockOpen, NODE_NAMED_IF_PREFIX) &&
                            isReviewedNamedGuardScope(blockOpen - NODE_NAMED_IF_PREFIX.size) &&
                            isReviewedNamedPredicateUse(
                                NamedEnvironmentPredicate.Node,
                                blockOpen,
                            )
                        ) ||
                    (
                        matchesBareIfBefore(blockOpen, NODE_DIRECT_IF_PREFIX) &&
                            isModuleLevel(blockOpen - NODE_DIRECT_IF_PREFIX.size) &&
                            hasOnlyReviewedRootProcessOccurrences()
                        )
                ) {
                    return ReviewedLoaderContext.NodeBlock
                }
            }
            if (blockPrefix.matchesExactly(DENO_BLOCK_BODY_PREFIX) &&
                matchesBareIfBefore(blockOpen, DENO_IF_PREFIX) &&
                isReviewedNamedGuardScope(blockOpen - DENO_IF_PREFIX.size) &&
                isReviewedNamedPredicateUse(NamedEnvironmentPredicate.Deno, blockOpen)
            ) {
                return ReviewedLoaderContext.DenoBlock
            }
            if (blockPrefix.matchesExactly(SKIKO_DEAD_BLOCK_BODY_PREFIX) &&
                matchesBareIfBefore(blockOpen, SKIKO_DEAD_IF_PREFIX)
            ) {
                return ReviewedLoaderContext.SkikoDeadBlock
            }
        }
        return if (isReviewedKotlinIoImport(index, specifier)) {
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
        val denoDeclaration = uniqueCanonicalDenoDeclaration() ?: return false
        val nodeGuardName = uniqueReviewedNamedGuardNameIndex(
            NamedEnvironmentPredicate.Node,
        ) ?: return false
        val denoGuardName = uniqueReviewedNamedGuardNameIndex(
            NamedEnvironmentPredicate.Deno,
        ) ?: return false
        val expectedGuardName = when (predicate) {
            NamedEnvironmentPredicate.Node -> nodeGuardName
            NamedEnvironmentPredicate.Deno -> denoGuardName
        }
        val prefixSize = when (predicate) {
            NamedEnvironmentPredicate.Node -> NODE_NAMED_IF_PREFIX.size
            NamedEnvironmentPredicate.Deno -> DENO_IF_PREFIX.size
        }
        val currentGuardName = useIndex - prefixSize + NAMED_IF_NAME_OFFSET
        if (currentGuardName != expectedGuardName) return false
        if (nodeDeclaration >= useIndex || denoDeclaration >= useIndex) return false
        if (hasAmbiguousSlashBefore(useIndex)) return false
        if (!hasOnlyReviewedPredicateOccurrences("isNodeJs", nodeDeclaration + 1, nodeGuardName)) {
            return false
        }
        if (!hasOnlyReviewedPredicateOccurrences("isDeno", denoDeclaration + 1, denoGuardName)) {
            return false
        }
        return hasOnlyReviewedNamedEnvironmentGlobals(nodeDeclaration, denoDeclaration)
    }

    private fun uniqueReviewedNamedGuardNameIndex(
        predicate: NamedEnvironmentPredicate,
    ): Int? {
        var match: Int? = null
        for (index in tokens.indices) {
            if (!isReviewedNamedGuardName(index, predicate)) continue
            if (match != null) return null
            match = index
        }
        return match
    }

    private fun isReviewedNamedGuardName(
        nameIndex: Int,
        predicate: NamedEnvironmentPredicate,
    ): Boolean {
        val predicateName = when (predicate) {
            NamedEnvironmentPredicate.Node -> "isNodeJs"
            NamedEnvironmentPredicate.Deno -> "isDeno"
        }
        if ((tokens.getOrNull(nameIndex) as? JsToken.Identifier)?.value != predicateName) {
            return false
        }
        val ifPrefix = when (predicate) {
            NamedEnvironmentPredicate.Node -> NODE_NAMED_IF_PREFIX
            NamedEnvironmentPredicate.Deno -> DENO_IF_PREFIX
        }
        val bodyPrefix = when (predicate) {
            NamedEnvironmentPredicate.Node -> NODE_BLOCK_BODY_PREFIX
            NamedEnvironmentPredicate.Deno -> DENO_BLOCK_BODY_PREFIX
        }
        val specifier = when (predicate) {
            NamedEnvironmentPredicate.Node -> "node:module"
            NamedEnvironmentPredicate.Deno -> "https://deno.land/std/path/mod.ts"
        }
        val ifStart = nameIndex - NAMED_IF_NAME_OFFSET
        val blockOpen = ifStart + ifPrefix.size
        if (blockOpen >= tokens.size) return false
        if (!matchesBareIfBefore(blockOpen, ifPrefix)) return false
        if (!isReviewedNamedGuardScope(ifStart)) return false
        if ((tokens.getOrNull(blockOpen) as? JsToken.Punctuation)?.value != "{") return false
        if (!matchesAt(blockOpen + 1, bodyPrefix)) return false
        val importIndex = blockOpen + 1 + bodyPrefix.size
        return (tokens.getOrNull(importIndex) as? JsToken.Identifier)?.value == "import" &&
            (tokens.getOrNull(importIndex + 1) as? JsToken.Punctuation)?.value == "(" &&
            (tokens.getOrNull(importIndex + 2) as? JsToken.StringLiteral)?.value == specifier &&
            (tokens.getOrNull(importIndex + 3) as? JsToken.Punctuation)?.value == ")"
    }

    private fun hasOnlyReviewedPredicateOccurrences(
        name: String,
        canonicalNameIndex: Int,
        guardNameIndex: Int,
    ): Boolean = tokens.indices.all { index ->
        (tokens[index] as? JsToken.Identifier)?.value != name ||
            index == canonicalNameIndex ||
            index == guardNameIndex ||
            isNegatedConjunctionRead(index)
    }

    private fun isNegatedConjunctionRead(index: Int): Boolean =
        (tokens.getOrNull(index - 1) as? JsToken.Punctuation)?.value == "!" &&
            (tokens.getOrNull(index + 1) as? JsToken.Punctuation)?.value == "&" &&
            (tokens.getOrNull(index + 2) as? JsToken.Punctuation)?.value == "&"

    private fun hasOnlyReviewedNamedEnvironmentGlobals(
        nodeDeclaration: Int,
        denoDeclaration: Int,
    ): Boolean =
        !hasEnvironmentNameString("process") &&
            !hasEnvironmentNameString("Deno") &&
            tokens.indices.all { index ->
                when ((tokens[index] as? JsToken.Identifier)?.value) {
                    "process" ->
                        isIdentifierRoleInMatch(
                            index,
                            "process",
                            nodeDeclaration,
                            NODE_DECLARATION,
                        )
                    "Deno" ->
                        isIdentifierRoleInMatch(index, "Deno", denoDeclaration, DENO_DECLARATION) ||
                            isDenoReadFileSync(index)
                    else -> true
                }
            }

    private fun hasEnvironmentNameString(name: String): Boolean =
        tokens.any { token -> (token as? JsToken.StringLiteral)?.value == name }

    private fun isDenoReadFileSync(index: Int): Boolean =
        (tokens.getOrNull(index + 1) as? JsToken.Punctuation)?.value == "." &&
            (tokens.getOrNull(index + 2) as? JsToken.Identifier)?.value == "readFileSync"

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

    private fun isReviewedNamedGuardScope(ifStart: Int): Boolean {
        if (isModuleLevel(ifStart)) return true
        val containingBlock = enclosingBlockOpen(ifStart) ?: return false
        val tryIndex = containingBlock - 1
        return isModuleLevel(tryIndex) &&
            (tokens.getOrNull(tryIndex) as? JsToken.Identifier)?.value == "try" &&
            !isMemberProperty(tryIndex)
    }

    private fun isReviewedKotlinIoImport(index: Int, specifier: String): Boolean {
        if (publicName != KOTLIN_IO_IMPORT_OBJECT_PUBLIC_NAME) return false
        val importOffset = KOTLIN_IO_IMPORT_OFFSET_BY_SPECIFIER[specifier] ?: return false
        val jsCodeRange = uniqueRootJsCodeObjectRange() ?: return false
        val groupStart = uniqueRootKotlinIoGroupStart(jsCodeRange) ?: return false
        if (index != groupStart + importOffset) return false
        return hasOnlyReviewedRootProcessOccurrences()
    }

    private fun uniqueRootKotlinIoGroupStart(jsCodeRange: IntRange): Int? {
        var result: Int? = null
        for (start in jsCodeRange) {
            if (!matchesAt(start, KOTLIN_IO_JS_CODE_GROUP)) continue
            if (start + KOTLIN_IO_JS_CODE_GROUP.size - 1 > jsCodeRange.last) continue
            if (enclosingBlockOpen(start) != jsCodeRange.first - 1) continue
            if (result != null) return null
            result = start
        }
        return result
    }

    private fun hasOnlyReviewedRootProcessOccurrences(): Boolean {
        if (hasEnvironmentNameString("process")) return false
        val nodeDeclaration = uniqueCanonicalNodeDeclaration()
        val jsCodeRange = uniqueRootJsCodeObjectRange()
        if (jsCodeRange != null && !hasOnlyReviewedRootJsCodeInitializers(jsCodeRange)) {
            return false
        }
        return tokens.indices.all { index ->
            if ((tokens[index] as? JsToken.Identifier)?.value != "process") {
                return@all true
            }
            if (nodeDeclaration != null &&
                isIdentifierRoleInMatch(index, "process", nodeDeclaration, NODE_DECLARATION)
            ) {
                return@all true
            }
            if (isIdentifierRoleInAnyMatch(index, "process", NODE_DIRECT_IF_PREFIX)) {
                return@all true
            }
            jsCodeRange != null && isReviewedJsCodeProcessOccurrence(index, jsCodeRange)
        }
    }

    private fun hasOnlyReviewedRootJsCodeInitializers(jsCodeRange: IntRange): Boolean {
        var cursor = jsCodeRange.first
        while (cursor <= jsCodeRange.last) {
            if (tokens.getOrNull(cursor) !is JsToken.StringLiteral) return false
            if ((tokens.getOrNull(cursor + 1) as? JsToken.Punctuation)?.value != ":") {
                return false
            }
            val reviewedEagerProperty = REVIEWED_EAGER_JS_CODE_PROPERTIES.firstOrNull { expected ->
                matchesAt(cursor, expected)
            }
            if (reviewedEagerProperty != null) {
                cursor += reviewedEagerProperty.size
                continue
            }
            val valueStart = cursor + 2
            if (!isDirectStoredArrow(valueStart)) return false
            val separator = directPropertySeparator(valueStart, jsCodeRange)
            cursor = if (separator == null) jsCodeRange.last + 1 else separator + 1
        }
        return true
    }

    private fun isDirectStoredArrow(valueStart: Int): Boolean {
        if ((tokens.getOrNull(valueStart) as? JsToken.Punctuation)?.value != "(") return false
        val parametersClose = matchingPunctuationClose(valueStart, "(", ")") ?: return false
        return (tokens.getOrNull(parametersClose + 1) as? JsToken.Punctuation)?.value == "=" &&
            (tokens.getOrNull(parametersClose + 2) as? JsToken.Punctuation)?.value == ">"
    }

    private fun directPropertySeparator(
        valueStart: Int,
        jsCodeRange: IntRange,
    ): Int? {
        var parentheses = 0
        var brackets = 0
        var braces = 0
        var templates = 0
        for (index in valueStart..jsCodeRange.last) {
            when (val token = tokens[index]) {
                is JsToken.TemplateBoundary -> templates += if (token.opening) 1 else -1
                is JsToken.Punctuation -> when (token.value) {
                    "(" -> parentheses++
                    ")" -> parentheses--
                    "[" -> brackets++
                    "]" -> brackets--
                    "{" -> braces++
                    "}" -> braces--
                    "," -> if (
                        parentheses == 0 && brackets == 0 && braces == 0 && templates == 0
                    ) {
                        return index
                    }
                }
                else -> Unit
            }
        }
        return null
    }

    private fun matchingPunctuationClose(
        open: Int,
        opening: String,
        closing: String,
    ): Int? {
        var depth = 0
        for (index in open + 1 until tokens.size) {
            val punctuation = tokens[index] as? JsToken.Punctuation ?: continue
            when (punctuation.value) {
                opening -> depth++
                closing -> if (depth == 0) return index else depth--
            }
        }
        return null
    }

    private fun isReviewedJsCodeProcessOccurrence(
        index: Int,
        jsCodeRange: IntRange,
    ): Boolean = REVIEWED_JS_CODE_PROCESS_PROPERTIES.any { expected ->
        expected.indices.any { offset ->
            val start = index - offset
            expected[offset] == identifier("process") &&
                start in jsCodeRange &&
                enclosingBlockOpen(start) == jsCodeRange.first - 1 &&
                matchesAt(start, expected)
        }
    }

    private fun uniqueRootJsCodeObjectRange(): IntRange? {
        var result: IntRange? = null
        for (start in tokens.indices) {
            if (!isModuleLevel(start) || !matchesAt(start, JS_CODE_OBJECT_PREFIX)) continue
            val open = start + JS_CODE_OBJECT_PREFIX.size - 1
            val close = matchingBlockClose(open) ?: return null
            if (result != null) return null
            result = (open + 1)..<close
        }
        return result
    }

    private fun matchingBlockClose(open: Int): Int? {
        var depth = 0
        for (index in open + 1 until tokens.size) {
            when (val token = tokens[index]) {
                is JsToken.TemplateBoundary -> if (!token.opening) return null
                is JsToken.Punctuation -> when (token.value) {
                    "{" -> depth++
                    "}" -> if (depth == 0) return index else depth--
                }
                else -> Unit
            }
        }
        return null
    }

    private fun isIdentifierRoleInAnyMatch(
        index: Int,
        name: String,
        expected: List<JsTokenShape>,
    ): Boolean = expected.indices.any { offset ->
        expected[offset] == identifier(name) && matchesAt(index - offset, expected)
    }

    private fun isIdentifierRoleInMatch(
        index: Int,
        name: String,
        matchStart: Int,
        expected: List<JsTokenShape>,
    ): Boolean = expected.indices.any { offset ->
        expected[offset] == identifier(name) && index == matchStart + offset
    }

    private fun hasAmbiguousSlashBefore(useIndex: Int): Boolean =
        tokens.subList(0, useIndex).any { token ->
            token is JsToken.Punctuation && token.value == "/"
        }

    private fun matchesBareIfBefore(
        endExclusive: Int,
        expected: List<JsTokenShape>,
    ): Boolean {
        if (!matchesBefore(endExclusive, expected)) return false
        val ifIndex = endExclusive - expected.size
        if (isMemberProperty(ifIndex)) return false
        val previous = tokens.getOrNull(ifIndex - 1) as? JsToken.Identifier
        return previous == null || previous.value == "else"
    }

    private fun isMemberProperty(identifierIndex: Int): Boolean =
        (tokens.getOrNull(identifierIndex - 1) as? JsToken.Punctuation)?.value in
            setOf(".", "#")

    private fun matchesBefore(
        endExclusive: Int,
        expected: List<JsTokenShape>,
    ): Boolean {
        val start = endExclusive - expected.size
        if (start < 0 || endExclusive > tokens.size) return false
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
        private const val NAMED_IF_NAME_OFFSET = 2

        private val KOTLIN_IO_PROPERTY_BY_SPECIFIER = mapOf(
            "node:buffer" to "kotlinx.io.node.loadBuffer",
            "node:os" to "kotlinx.io.node.loadOs",
            "node:path" to "kotlinx.io.node.loadPath",
            "node:fs" to "kotlinx.io.node.loadFs",
        )

        private val JS_CODE_OBJECT_PREFIX = listOf(
            identifier("const"),
            identifier("js_code"),
            punctuation("="),
            punctuation("{"),
        )

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
        private val KOTLIN_IO_JS_CODE_PROPERTIES =
            KOTLIN_IO_PROPERTY_BY_SPECIFIER.map { (specifier, propertyName) ->
                javascriptShape(
                    """
                    '$propertyName' :
                        ((module) => () => module)(((typeof process !== 'undefined') &&
                        (process.release.name === 'node')) ?
                        await import('$specifier') : null),
                    """.trimIndent(),
                )
            }
        private val KOTLIN_IO_JS_CODE_GROUP = KOTLIN_IO_JS_CODE_PROPERTIES.flatten()
        private val KOTLIN_IO_IMPORT_OFFSET_BY_SPECIFIER = buildMap {
            var groupOffset = 0
            KOTLIN_IO_PROPERTY_BY_SPECIFIER.keys.zip(KOTLIN_IO_JS_CODE_PROPERTIES)
                .forEach { (specifier, propertyShape) ->
                    val importOffset = propertyShape.indexOf(identifier("import"))
                    require(importOffset >= 0) {
                        "Reviewed Kotlin IO property does not contain its import token"
                    }
                    put(specifier, groupOffset + importOffset)
                    groupOffset += propertyShape.size
                }
        }
        private val REVIEWED_JS_CODE_PROCESS_PROPERTIES = listOf(
            javascriptShape(
                """
                'kotlinx.coroutines.tryGetProcess' :
                    () => (typeof(process) !== 'undefined' &&
                    typeof(process.nextTick) === 'function') ? process : null,
                """.trimIndent(),
            ),
            javascriptShape(
                """
                'kotlinx.coroutines.createScheduleMessagePoster' :
                    (process) => () => Promise.resolve(0).then(process),
                """.trimIndent(),
            ),
            javascriptShape(
                """
                'kotlinx.coroutines.subscribeToWindowMessages' : (window, process) => {
                    const handler = (event) => {
                        if (event.source == window && event.data == 'dispatchCoroutine') {
                            event.stopPropagation();
                            process();
                        }
                    }
                    window.addEventListener('message', handler, true);
                },
                """.trimIndent(),
            ),
            javascriptShape(
                """
                'io.ktor.util.hasNodeApi' : () =>
                    (typeof process !== 'undefined' &&
                        process.versions != null &&
                        process.versions.node != null) ||
                    (typeof window !== 'undefined' &&
                        typeof window.process !== 'undefined' &&
                        window.process.versions != null &&
                        window.process.versions.node != null),
                """.trimIndent(),
            ),
            javascriptShape(
                """
                'io.ktor.util.logging.getKtorLogLevel' :
                    () => process ? process.env.KTOR_LOG_LEVEL : null,
                """.trimIndent(),
            ),
        ) + KOTLIN_IO_JS_CODE_PROPERTIES
        private val REVIEWED_EAGER_JS_CODE_PROPERTIES = listOf(
            javascriptShape(
                """
                'kotlin.wasm.internal.jsThrow' :
                    wasmTag === wasmJsTag ? (e) => { throw e; } : () => {},
                """.trimIndent(),
            ),
            javascriptShape(
                """
                'kotlin.wasm.internal.externrefHashCode' :
                    (() => {
                        const dataView = new DataView(new ArrayBuffer(8));
                        function numberHashCode(obj) {
                            if ((obj | 0) === obj) {
                                return obj | 0;
                            } else {
                                dataView.setFloat64(0, obj, true);
                                return (dataView.getInt32(0, true) * 31 | 0) +
                                    dataView.getInt32(4, true) | 0;
                            }
                        }

                        const hashCodes = new WeakMap();
                        function getObjectHashCode(obj) {
                            const res = hashCodes.get(obj);
                            if (res === undefined) {
                                const POW_2_32 = 4294967296;
                                const hash = (Math.random() * POW_2_32) | 0;
                                hashCodes.set(obj, hash);
                                return hash;
                            }
                            return res;
                        }

                        function getStringHashCode(str) {
                            var hash = 0;
                            for (var i = 0; i < str.length; i++) {
                                var code = str.charCodeAt(i);
                                hash = (hash * 31 + code) | 0;
                            }
                            return hash;
                        }

                        return (obj) => {
                            if (obj == null) {
                                return 0;
                            }
                            switch (typeof obj) {
                                case "object":
                                case "function":
                                    return getObjectHashCode(obj);
                                case "number":
                                    return numberHashCode(obj);
                                case "boolean":
                                    return obj ? 1231 : 1237;
                                default:
                                    return getStringHashCode(String(obj));
                            }
                        }
                    })(),
                """.trimIndent(),
            ),
        ) + KOTLIN_IO_JS_CODE_PROPERTIES
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

    data class TemplateLiteral(override val start: Int) : JsToken

    data class NumericLiteral(val value: String, override val start: Int) : JsToken

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

    data class NumericLiteral(override val value: String) : JsTokenShape
}

private fun identifier(value: String): JsTokenShape = JsTokenShape.Identifier(value)

private fun stringLiteral(value: String): JsTokenShape = JsTokenShape.StringLiteral(value)

private fun punctuation(value: String): JsTokenShape = JsTokenShape.Punctuation(value)

private fun javascriptShape(source: String): List<JsTokenShape> = tokenize(source).map { token ->
    when (token) {
        is JsToken.Identifier -> JsTokenShape.Identifier(token.value)
        is JsToken.StringLiteral -> JsTokenShape.StringLiteral(token.value)
        is JsToken.NumericLiteral -> JsTokenShape.NumericLiteral(token.value)
        is JsToken.Punctuation -> JsTokenShape.Punctuation(token.value)
        is JsToken.RegexLiteral,
        is JsToken.TemplateLiteral,
        is JsToken.TemplateBoundary,
        -> error("Reviewed JavaScript shapes may only contain literal code tokens")
    }
}

private fun List<JsToken>.matchesExactly(expected: List<JsTokenShape>): Boolean =
    size == expected.size && indices.all { index ->
        when (val token = this[index]) {
            is JsToken.Identifier ->
                expected[index] == JsTokenShape.Identifier(token.value)

            is JsToken.StringLiteral ->
                expected[index] == JsTokenShape.StringLiteral(token.value)

            is JsToken.RegexLiteral -> false

            is JsToken.TemplateLiteral -> false

            is JsToken.NumericLiteral ->
                expected[index] == JsTokenShape.NumericLiteral(token.value)

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
                character.code > ASCII_MAX_CODE_POINT -> throw IllegalArgumentException(
                    "Unreviewed non-ASCII JavaScript syntax outside an opaque literal",
                )
                character.isWhitespace() -> index++
                character == '/' && source.getOrNull(index + 1) == '/' -> {
                    requireCommentOpenerIsNotEscaped()
                    scanLineComment()
                }

                character == '/' && source.getOrNull(index + 1) == '*' -> {
                    requireCommentOpenerIsNotEscaped()
                    scanBlockComment()
                }
                character == '/' && canStartRegexLiteral() -> scanRegexLiteral()
                character == '/' && inTemplateSubstitution ->
                    throw IllegalArgumentException(
                        "Unreviewed slash syntax inside JavaScript template substitution",
                    )

                character == '/' -> {
                    require(canEmitDivisionOperator()) { "Unreviewed slash context" }
                    tokens += JsToken.Punctuation(character.toString(), index)
                    index++
                }

                character == '\'' || character == '"' -> scanString()
                character == '`' -> scanTemplate()
                character == '\\' -> throw IllegalArgumentException(
                    "Unreviewed JavaScript escape outside an opaque literal",
                )
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

                character.isDigit() -> scanNumericLiteral()

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
        while (index < source.length && source[index] !in JAVASCRIPT_LINE_TERMINATORS) index++
        if (index >= source.length) return
        if (source[index] == '\r' && source.getOrNull(index + 1) == '\n') {
            index += 2
        } else {
            index++
        }
    }

    private fun requireCommentOpenerIsNotEscaped() {
        require(source.getOrNull(index - 1) != '\\') {
            "Unreviewed escaped slash before JavaScript comment opener"
        }
    }

    private fun scanBlockComment() {
        val end = source.indexOf("*/", index + 2)
        require(end >= 0) { "Unterminated JavaScript block comment" }
        index = end + 2
    }

    private fun canStartRegexLiteral(): Boolean {
        val previous = tokens.lastOrNull() as? JsToken.Punctuation ?: return false
        return previous.value in REVIEWED_REGEX_PREFIXES
    }

    private fun canEmitDivisionOperator(): Boolean {
        val previousIndex = tokens.lastIndex
        val previous = tokens.getOrNull(previousIndex) ?: return false
        if (tokenEndsExpression(previous, previousIndex)) return true
        val operator = previous as? JsToken.Punctuation ?: return false
        val repeated = tokens.getOrNull(previousIndex - 1) as? JsToken.Punctuation ?: return false
        val operandIndex = previousIndex - 2
        val operand = tokens.getOrNull(operandIndex) ?: return false
        return operator.value in setOf("+", "-") &&
            operator.value == repeated.value &&
            tokenEndsExpression(operand, operandIndex)
    }

    private fun tokenEndsExpression(token: JsToken, tokenIndex: Int): Boolean = when (token) {
        is JsToken.Identifier ->
            isMemberProperty(tokenIndex) ||
                token.value !in AMBIGUOUS_SLASH_IDENTIFIERS &&
                !isUninitializedVariableBinding(tokenIndex) &&
                !isControlFlowLabel(tokenIndex)

        is JsToken.StringLiteral -> !isStaticModuleSpecifier(tokenIndex)

        is JsToken.RegexLiteral,
        is JsToken.TemplateLiteral,
        is JsToken.NumericLiteral,
        -> true

        is JsToken.Punctuation -> when (token.value) {
            "]" -> true
            ")" -> closesDivisionSafeParenthesizedExpression(tokenIndex)
            else -> false
        }
        is JsToken.TemplateBoundary -> false
    }

    private fun isStaticModuleSpecifier(stringIndex: Int): Boolean {
        val precedingIndex = stringIndex - 1
        val preceding = tokens.getOrNull(precedingIndex) as? JsToken.Identifier ?: return false
        if (isMemberProperty(precedingIndex)) return false
        return preceding.value == "import" ||
            preceding.value == "from" && isStaticModuleFromKeyword(precedingIndex)
    }

    private fun isStaticModuleFromKeyword(fromIndex: Int): Boolean {
        if (isExportNamespaceAliasFromKeyword(fromIndex)) return true
        var braces = 0
        for (candidateIndex in fromIndex - 1 downTo 0) {
            when (val candidate = tokens[candidateIndex]) {
                is JsToken.Identifier -> {
                    if (braces == 0 && candidate.value == "default") return false
                    if (braces == 0 &&
                        candidate.value in MODULE_DECLARATION_KEYWORDS &&
                        !isMemberProperty(candidateIndex)
                    ) {
                        return true
                    }
                }

                is JsToken.StringLiteral -> if (braces == 0) return false
                is JsToken.Punctuation -> when (candidate.value) {
                    "}" -> braces++
                    "{" -> if (braces > 0) braces-- else return false
                    ",", "*" -> Unit
                    else -> return false
                }

                else -> return false
            }
        }
        return false
    }

    private fun isExportNamespaceAliasFromKeyword(fromIndex: Int): Boolean {
        val alias = tokens.getOrNull(fromIndex - 1)
        if (alias !is JsToken.Identifier && alias !is JsToken.StringLiteral) return false
        val asKeyword = tokens.getOrNull(fromIndex - 2) as? JsToken.Identifier ?: return false
        val star = tokens.getOrNull(fromIndex - 3) as? JsToken.Punctuation ?: return false
        val exportIndex = fromIndex - 4
        val exportKeyword = tokens.getOrNull(exportIndex) as? JsToken.Identifier ?: return false
        return asKeyword.value == "as" &&
            star.value == "*" &&
            exportKeyword.value == "export" &&
            !isMemberProperty(exportIndex)
    }

    private fun isUninitializedVariableBinding(identifierIndex: Int): Boolean {
        val precedingIndex = identifierIndex - 1
        return when (val preceding = tokens.getOrNull(precedingIndex)) {
            is JsToken.Identifier ->
                preceding.value in VARIABLE_DECLARATION_KEYWORDS &&
                    !isMemberProperty(precedingIndex)

            is JsToken.Punctuation ->
                preceding.value == "," && commaBelongsToVariableDeclaration(precedingIndex)

            else -> false
        }
    }

    private fun commaBelongsToVariableDeclaration(commaIndex: Int): Boolean {
        var parentheses = 0
        var brackets = 0
        var braces = 0
        for (candidateIndex in commaIndex - 1 downTo 0) {
            when (val candidate = tokens[candidateIndex]) {
                is JsToken.Identifier -> if (
                    parentheses == 0 && brackets == 0 && braces == 0 &&
                    candidate.value in VARIABLE_DECLARATION_KEYWORDS &&
                    !isMemberProperty(candidateIndex)
                ) {
                    return true
                }

                is JsToken.Punctuation -> when (candidate.value) {
                    ")" -> parentheses++
                    "]" -> brackets++
                    "}" -> braces++
                    "(" -> if (parentheses > 0) parentheses-- else return false
                    "[" -> if (brackets > 0) brackets-- else return false
                    "{" -> if (braces > 0) braces-- else return false
                    ";" -> if (parentheses == 0 && brackets == 0 && braces == 0) {
                        return false
                    }

                    else -> Unit
                }

                else -> Unit
            }
        }
        return false
    }

    private fun isControlFlowLabel(identifierIndex: Int): Boolean {
        val precedingIndex = identifierIndex - 1
        val preceding = tokens.getOrNull(precedingIndex) as? JsToken.Identifier ?: return false
        if (preceding.value !in CONTROL_FLOW_LABEL_KEYWORDS || isMemberProperty(precedingIndex)) {
            return false
        }
        val identifier = tokens[identifierIndex] as JsToken.Identifier
        return source.substring(preceding.start + preceding.value.length, identifier.start)
            .none { it in JAVASCRIPT_LINE_TERMINATORS }
    }

    private fun closesDivisionSafeParenthesizedExpression(closeIndex: Int): Boolean {
        var nestedParentheses = 0
        for (candidateIndex in closeIndex - 1 downTo 0) {
            val punctuation = tokens[candidateIndex] as? JsToken.Punctuation ?: continue
            when (punctuation.value) {
                ")" -> nestedParentheses++
                "(" -> if (nestedParentheses > 0) {
                    nestedParentheses--
                } else {
                    return !isControlHeaderOpeningParenthesis(candidateIndex)
                }
            }
        }
        return false
    }

    private fun isControlHeaderOpeningParenthesis(openIndex: Int): Boolean {
        val precedingIndex = openIndex - 1
        val preceding = tokens.getOrNull(precedingIndex) as? JsToken.Identifier ?: return false
        if (isMemberProperty(precedingIndex)) return false
        if (preceding.value in CONTROL_HEADER_KEYWORDS) return true
        return preceding.value == "await" &&
            (tokens.getOrNull(precedingIndex - 1) as? JsToken.Identifier)?.value == "for"
    }

    private fun isMemberProperty(identifierIndex: Int): Boolean {
        val preceding = tokens.getOrNull(identifierIndex - 1) as? JsToken.Punctuation
        val beforePreceding = tokens.getOrNull(identifierIndex - 2) as? JsToken.Punctuation
        return preceding?.value == "." ||
            preceding?.value == "#" && beforePreceding?.value == "."
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
                    require(!inCharacterClass) {
                        "Unreviewed nested character class in JavaScript regex literal"
                    }
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
        val start = index
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
                    tokens += JsToken.TemplateLiteral(start)
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
            source[index].code <= ASCII_MAX_CODE_POINT &&
            (source[index].isLetterOrDigit() || source[index] == '_' || source[index] == '$')
        ) {
            index++
        }
        tokens += JsToken.Identifier(source.substring(start, index), start)
    }

    private fun scanNumericLiteral() {
        val start = index
        if (source[index] == '0' && source.getOrNull(index + 1)?.lowercaseChar() in setOf('x', 'b', 'o')) {
            index += 2
            while (source.getOrNull(index)?.let { it.isLetterOrDigit() || it == '_' } == true) index++
        } else {
            while (source.getOrNull(index)?.let { it.isDigit() || it == '_' } == true) index++
            if (source.getOrNull(index) == '.') {
                index++
                while (source.getOrNull(index)?.let { it.isDigit() || it == '_' } == true) index++
            }
            if (source.getOrNull(index)?.lowercaseChar() == 'e') {
                index++
                if (source.getOrNull(index) in setOf('+', '-')) index++
                while (source.getOrNull(index)?.let { it.isDigit() || it == '_' } == true) index++
            }
        }
        if (source.getOrNull(index) == 'n') index++
        tokens += JsToken.NumericLiteral(source.substring(start, index), start)
    }

    private companion object {
        val REVIEWED_REGEX_PREFIXES = setOf("(", "=")
        val CONTROL_HEADER_KEYWORDS = setOf("if", "for", "while", "switch", "with", "catch")
        val MODULE_DECLARATION_KEYWORDS = setOf("import", "export")
        val VARIABLE_DECLARATION_KEYWORDS = setOf("let", "var")
        val CONTROL_FLOW_LABEL_KEYWORDS = setOf("break", "continue")
        val JAVASCRIPT_LINE_TERMINATORS = setOf('\n', '\r', '\u2028', '\u2029')
        const val ASCII_MAX_CODE_POINT = 0x7f
        val AMBIGUOUS_SLASH_IDENTIFIERS = setOf(
            "await", "break", "case", "catch", "class", "const", "continue", "debugger",
            "default", "delete", "do", "else", "export", "extends", "finally", "for",
            "function", "if", "import", "in", "instanceof", "let", "new", "of", "return",
            "static", "super", "switch", "throw", "try", "typeof", "var", "void", "while",
            "with", "yield",
        )
    }
}

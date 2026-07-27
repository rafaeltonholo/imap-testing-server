package mail.sandbox.dashboard.server.web

import java.net.URL
import java.nio.file.Files
import java.nio.file.Path
import java.util.Collections
import java.util.Enumeration
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.writeBytes
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class WebAssetBundleTest {
    @Test
    fun resolvesTheCompleteReviewedLinkerClasspathAndComposeResourceClosure() {
        withFixture { fixture ->
            val bundle = fixture.load()

            assertEquals("/assets/gate.mjs", bundle.entryAssetPath)
            assertTrue("/assets/loader.mjs" in bundle.assetPaths)
            assertTrue("/assets/dynamic.mjs" in bundle.assetPaths)
            assertTrue("/assets/exported.mjs" in bundle.assetPaths)
            assertTrue("/assets/nested/static.mjs" in bundle.assetPaths)
            assertTrue("/assets/gate.wasm" in bundle.assetPaths)
            assertTrue("/assets/skiko.mjs" in bundle.assetPaths)
            assertTrue("/assets/skiko.wasm" in bundle.assetPaths)
            assertTrue("/assets/js-joda.esm.js" in bundle.assetPaths)
            assertTrue(
                "/assets/composeResources/$GENERATED_RESOURCE_PACKAGE/files/gate-proof.txt" in
                    bundle.assetPaths,
            )
            assertTrue(
                "/assets/composeResources/$GENERATED_RESOURCE_PACKAGE/nested/images/proof.svg" in
                    bundle.assetPaths,
            )
            assertTrue(
                "/assets/composeResources/$GENERATED_RESOURCE_PACKAGE/nested/fonts/proof.woff2" in
                    bundle.assetPaths,
            )

            assertEquals(SKIKO_MJS_SHA256, bundle.requireAsset("/assets/skiko.mjs").sha256)
            assertEquals(SKIKO_WASM_SHA256, bundle.requireAsset("/assets/skiko.wasm").sha256)
            assertEquals(JODA_SHA256, bundle.requireAsset("/assets/js-joda.esm.js").sha256)
            assertEquals(
                GATE_PROOF_SHA256,
                bundle.requireAsset(
                    "/assets/composeResources/$GENERATED_RESOURCE_PACKAGE/files/gate-proof.txt",
                ).sha256,
            )
            assertEquals("text/javascript", bundle.requireAsset("/assets/gate.mjs").contentType)
            assertEquals("text/javascript", bundle.requireAsset("/assets/js-joda.esm.js").contentType)
            assertEquals("application/wasm", bundle.requireAsset("/assets/gate.wasm").contentType)
            assertEquals(
                "image/svg+xml",
                bundle.requireAsset(
                    "/assets/composeResources/$GENERATED_RESOURCE_PACKAGE/nested/images/proof.svg",
                ).contentType,
            )
            assertEquals(
                "font/woff2",
                bundle.requireAsset(
                    "/assets/composeResources/$GENERATED_RESOURCE_PACKAGE/nested/fonts/proof.woff2",
                ).contentType,
            )
            val reviewedResourceMimes = mapOf(
                "nested/styles/proof.css" to "text/css",
                "nested/data/proof.json" to "application/json",
                "nested/text/readme.txt" to "text/plain",
                "nested/images/proof.png" to "image/png",
                "nested/images/proof.jpg" to "image/jpeg",
                "nested/images/proof.gif" to "image/gif",
                "nested/images/proof.webp" to "image/webp",
                "nested/fonts/proof.woff" to "font/woff",
                "nested/fonts/proof.ttf" to "font/ttf",
                "nested/fonts/proof.otf" to "font/otf",
            )
            reviewedResourceMimes.forEach { (relativePath, expectedMime) ->
                assertEquals(
                    expectedMime,
                    bundle.requireAsset(
                        "/assets/composeResources/$GENERATED_RESOURCE_PACKAGE/$relativePath",
                    ).contentType,
                    relativePath,
                )
            }
        }
    }

    @Test
    fun acceptsOnlyTheReviewedEnvironmentDeadGeneratedLoaders() {
        withFixture { fixture ->
            fixture.load()

            fixture.entry.writeText(
                fixture.entry.readText() +
                    "\nif (maybeNode) await import(/* webpackIgnore: true */'node:module')\n",
            )

            val failure = assertFailsWith<IllegalArgumentException> { fixture.load() }
            assertTrue(failure.message.orEmpty().lowercase().contains("unreviewed dynamic import"))
        }
    }

    @Test
    fun ignoresImportAndUrlDecoysInsideCommentsStringsAndTemplates() {
        withFixture { fixture ->
            fixture.entry.writeText(
                fixture.entry.readText() +
                    """

                    // import 'comment-decoy'
                    const quoted = "new URL('./quoted.wasm', import.meta.url)"
                    const templated = `await import('template-decoy')`
                    /* export { value } from "block-comment-decoy" */
                    """.trimIndent(),
            )

            fixture.load()
        }
    }

    @Test
    fun rejectsUnreviewedImportKindsAndNonLiteralDynamicImports() {
        val invalidStatements = mapOf(
            "bare" to "import 'other-package'",
            "absolute" to "import '/private/runtime.mjs'",
            "network" to "export { value } from 'https://example.test/runtime.mjs'",
            "non-literal dynamic" to "await import(runtimeModule)",
            "unreviewed dynamic Joda" to "await import('@js-joda/core')",
            "unreviewed Joda re-export" to
                "export { LocalDate } from '@js-joda/core'",
            "non-literal URL" to
                "new URL(runtimePrefix + runtimeFile, import.meta.url)",
            "absolute URL" to "new URL('/runtime.wasm', import.meta.url)",
            "query" to "import './dynamic.mjs?cache=off'",
            "fragment" to "new URL('./gate.wasm#bytes', import.meta.url)",
        )

        invalidStatements.forEach { (label, statement) ->
            withFixture { fixture ->
                fixture.entry.writeText(fixture.entry.readText() + "\n$statement\n")

                val failure = assertFailsWith<IllegalArgumentException>(label) { fixture.load() }
                assertTrue(
                    failure.message.orEmpty().lowercase().contains("unreviewed") ||
                        failure.message.orEmpty().lowercase().contains("relative"),
                    "$label produced: ${failure.message}",
                )
            }
        }
    }

    @Test
    fun rejectsTraversalMissingReferencesAndNormalizedAliases() {
        val invalidReferences = mapOf(
            "traversal" to "../outside.mjs",
            "missing" to "./missing.mjs",
            "duplicate normalized path" to ".//dynamic.mjs",
        )

        invalidReferences.forEach { (label, reference) ->
            withFixture { fixture ->
                if (label == "traversal") {
                    fixture.projectRoot.resolve("outside.mjs").writeText("export const outside = true")
                }
                fixture.entry.writeText(
                    fixture.entry.readText() + "\nimport '$reference'\n",
                )

                val failure = assertFailsWith<IllegalArgumentException>(label) { fixture.load() }
                assertTrue(
                    failure.message.orEmpty().contains("outside") ||
                        failure.message.orEmpty().contains("missing") ||
                        failure.message.orEmpty().contains("duplicate normalized"),
                    "$label produced: ${failure.message}",
                )
            }
        }
    }

    @Test
    fun rejectsNonCanonicalRootsSymlinksAndDirectoriesOutsideTheProject() {
        withFixture { fixture ->
            val nonCanonical = fixture.linkerDirectory.resolve("..").resolve("linker")
            val nonCanonicalFailure = assertFailsWith<IllegalArgumentException> {
                WebAssetBundle.load(
                    projectRoot = fixture.projectRoot,
                    linkerDirectory = nonCanonical,
                    composeResourcesDirectory = fixture.composeResourcesDirectory,
                    entryFileName = "gate.mjs",
                )
            }
            assertTrue(nonCanonicalFailure.message.orEmpty().contains("canonical"))
        }

        withFixture { fixture ->
            val outsideProject = createTempDirectory("gate-assets-outside").toRealPath()
            val outsideLinker = outsideProject.resolve("linker").createDirectories()
            fixture.linkerDirectory.toFile().copyRecursively(outsideLinker.toFile(), overwrite = true)

            val outsideFailure = assertFailsWith<IllegalArgumentException> {
                WebAssetBundle.load(
                    projectRoot = fixture.projectRoot,
                    linkerDirectory = outsideLinker,
                    composeResourcesDirectory = fixture.composeResourcesDirectory,
                    entryFileName = "gate.mjs",
                )
            }
            assertTrue(outsideFailure.message.orEmpty().contains("outside"))
        }

        withFixture { fixture ->
            val target = fixture.projectRoot.resolve("symlink-target.mjs").apply {
                writeText("export const linked = true")
            }
            Files.createSymbolicLink(fixture.linkerDirectory.resolve("linked.mjs"), target)
            fixture.entry.writeText(fixture.entry.readText() + "\nimport './linked.mjs'\n")

            val symlinkFailure = assertFailsWith<IllegalArgumentException> { fixture.load() }
            assertTrue(symlinkFailure.message.orEmpty().contains("symbolic link"))
        }

        withFixture { fixture ->
            val target = fixture.projectRoot.resolve("resource-target.txt").apply {
                writeText("linked resource")
            }
            Files.createSymbolicLink(
                fixture.composeResourcesDirectory.resolve("linked.txt"),
                target,
            )

            val symlinkFailure = assertFailsWith<IllegalArgumentException> { fixture.load() }
            assertTrue(symlinkFailure.message.orEmpty().contains("symbolic link"))
        }
    }

    @Test
    fun requiresExplicitMjsEntryBothWasmBinariesAndReviewedResourceExtensions() {
        withFixture { fixture ->
            val badEntry = assertFailsWith<IllegalArgumentException> {
                WebAssetBundle.load(
                    projectRoot = fixture.projectRoot,
                    linkerDirectory = fixture.linkerDirectory,
                    composeResourcesDirectory = fixture.composeResourcesDirectory,
                    entryFileName = "../gate.mjs",
                )
            }
            assertTrue(badEntry.message.orEmpty().contains("entry"))
        }

        withFixture { fixture ->
            fixture.entry.writeText(
                fixture.entry.readText().replace(
                    "new URL('./gate.wasm', import.meta.url)",
                    "const applicationWasmWasRemoved = true",
                ),
            )
            val noApplicationWasm = assertFailsWith<IllegalArgumentException> { fixture.load() }
            assertTrue(noApplicationWasm.message.orEmpty().contains("application Wasm"))
        }

        withFixture { fixture ->
            fixture.composeResourcesDirectory.resolve("unknown.bin").writeBytes(byteArrayOf(1))
            val unknownExtension = assertFailsWith<IllegalArgumentException> { fixture.load() }
            assertTrue(unknownExtension.message.orEmpty().contains("extension"))
        }
    }

    @Test
    fun rejectsDuplicatePublicPathsInThePinnedClasspathManifest() {
        withFixture { fixture ->
            val duplicateRuntime = productionWebRuntimeResources() +
                PinnedClasspathAsset(
                    publicFileName = "skiko.mjs",
                    classpathResourceName = "skiko.mjs",
                    expectedSha256 = SKIKO_MJS_SHA256,
                )

            val failure = assertFailsWith<IllegalArgumentException> {
                fixture.load(runtimeResources = duplicateRuntime)
            }
            assertTrue(failure.message.orEmpty().contains("duplicate normalized"))
        }
    }

    @Test
    fun rejectsChangedPinnedHashesMarkerBytesAndAmbiguousClasspathResources() {
        withFixture { fixture ->
            val changedPin = productionWebRuntimeResources().map { runtime ->
                if (runtime.publicFileName == "skiko.mjs") {
                    runtime.copy(expectedSha256 = "0".repeat(64))
                } else {
                    runtime
                }
            }
            val changedPinFailure = assertFailsWith<IllegalArgumentException> {
                fixture.load(runtimeResources = changedPin)
            }
            assertTrue(changedPinFailure.message.orEmpty().contains("SHA-256"))
        }

        withFixture { fixture ->
            fixture.composeResourcesDirectory.resolve("files/gate-proof.txt")
                .writeText("changed marker\n")

            val markerFailure = assertFailsWith<IllegalArgumentException> { fixture.load() }
            assertTrue(markerFailure.message.orEmpty().contains("SHA-256"))
        }

        withFixture { fixture ->
            val parent = javaClass.classLoader
            val duplicateClasspath = object : ClassLoader(parent) {
                override fun getResources(name: String): Enumeration<URL> {
                    if (name != "skiko.mjs") return super.getResources(name)
                    val resource = requireNotNull(parent.getResource(name))
                    return Collections.enumeration(listOf(resource, resource))
                }
            }

            val duplicateFailure = assertFailsWith<IllegalArgumentException> {
                fixture.load(classLoader = duplicateClasspath)
            }
            assertTrue(duplicateFailure.message.orEmpty().contains("resolved 2 times"))
        }
    }

    @Test
    fun snapshotsValidatedBytesAndDoesNotExposeMutableManifestStorage() {
        withFixture { fixture ->
            val original = fixture.entry.readText().encodeToByteArray()
            val bundle = fixture.load()
            val asset = bundle.requireAsset("/assets/gate.mjs")

            fixture.entry.writeText("changed after startup")
            val callerCopy = asset.bytes
            callerCopy[0] = (callerCopy[0] + 1).toByte()

            assertTrue(original.contentEquals(bundle.requireAsset("/assets/gate.mjs").bytes))
            assertEquals(sha256ForTest(original), bundle.requireAsset("/assets/gate.mjs").sha256)
        }
    }

    @Test
    fun requiresAllStartupEnvironmentInputsAndLoadsOnlyTheirCanonicalRoots() {
        withFixture { fixture ->
            val complete = mapOf(
                "DASHBOARD_WEB_ASSETS" to fixture.linkerDirectory.toString(),
                "DASHBOARD_WEB_RESOURCES" to fixture.composeResourcesDirectory.toString(),
                "DASHBOARD_WEB_ENTRY" to "gate.mjs",
            )

            complete.keys.forEach { missing ->
                val failure = assertFailsWith<IllegalArgumentException> {
                    WebAssetBundle.fromEnvironment(
                        environment = complete - missing,
                        projectRoot = fixture.projectRoot,
                    )
                }
                assertTrue(failure.message.orEmpty().contains(missing))
            }

            val loaded = WebAssetBundle.fromEnvironment(
                environment = complete,
                projectRoot = fixture.projectRoot,
            )
            assertEquals("/assets/gate.mjs", loaded.entryAssetPath)
        }
    }
}

internal const val GENERATED_RESOURCE_PACKAGE =
    "mail.sandbox.dashboard.web.generated.resources"
internal const val SKIKO_MJS_SHA256 =
    "5dc3302763d61014d4a3277727f6e1af041741ae1f0efcc2acc21f2924cad99e"
internal const val SKIKO_WASM_SHA256 =
    "69afd1fba0567fc79515d97bac5c0670cfeb180284823f986199637f154a9bbe"
internal const val JODA_SHA256 =
    "a716a37f4c3bb47f8795688e1cd6451130a08d825d8a6df664ef72b349ec445b"
internal const val GATE_PROOF_SHA256 =
    "7b0f843ebd49d2709bcd8e3d1021db98e68413823647895d8377a6657f5e6960"

internal class WebBundleFixture(
    val projectRoot: Path,
    val linkerDirectory: Path,
    val composeResourcesDirectory: Path,
) {
    val entry: Path = linkerDirectory.resolve("gate.mjs")

    fun load(
        runtimeResources: List<PinnedClasspathAsset> = productionWebRuntimeResources(),
        classLoader: ClassLoader = WebAssetBundleTest::class.java.classLoader,
    ): WebAssetBundle = WebAssetBundle.load(
        projectRoot = projectRoot,
        linkerDirectory = linkerDirectory,
        composeResourcesDirectory = composeResourcesDirectory,
        entryFileName = "gate.mjs",
        classLoader = classLoader,
        runtimeResources = runtimeResources,
    )
}

internal fun withFixture(block: (WebBundleFixture) -> Unit) {
    val projectRoot = createTempDirectory("gate-assets").toRealPath()
    val linker = projectRoot.resolve("linker").createDirectories().toRealPath()
    val resources = projectRoot.resolve("resources").createDirectories().toRealPath()
    val fixture = WebBundleFixture(projectRoot, linker, resources)

    fixture.entry.writeText(
        """
        import { boot } from './loader.mjs'
        await import(/* gate fixture */ "./dynamic.mjs")
        export { signal } from "./exported.mjs"
        new URL('./gate.wasm', import.meta.url)

        const isNodeJs = (typeof process !== 'undefined') && (process.release.name === 'node');
        const isDeno = !isNodeJs && (typeof Deno !== 'undefined')
        if (isNodeJs) {
          const module = await import(/* webpackIgnore: true */'node:module');
        }
        if (isDeno) {
          const path = await import(/* webpackIgnore: true */'https://deno.land/std/path/mod.ts');
        }
        """.trimIndent(),
    )
    linker.resolve("loader.mjs").writeText(
        """
        import * as skiko from './skiko.mjs'
        import * as joda from '@js-joda/core'
        import './nested/static.mjs'

        if (typeof process !== 'undefined' && process.release.name === 'node') {
            const module = await import(/* webpackIgnore: true */'node:module');
        }
        const persistModule =
            (globalThis.module = (typeof process !== 'undefined') && (process.release.name === 'node') ?
                await import(/* webpackIgnore: true */'node:module') : void 0, () => {})
        """.trimIndent(),
    )
    linker.resolve("dynamic.mjs").writeText("export const dynamic = true")
    linker.resolve("exported.mjs").writeText("export const signal = true")
    linker.resolve("nested").createDirectories()
        .resolve("static.mjs").writeText("export const boot = true")
    linker.resolve("gate.wasm").writeBytes(byteArrayOf(0, 97, 115, 109))

    resources.resolve("files").createDirectories()
        .resolve("gate-proof.txt")
        .writeText("GATE_RESOURCE: toolchain-compose-resource-ok\n")
    resources.resolve("nested/images").createDirectories()
        .resolve("proof.svg")
        .writeText("<svg xmlns=\"http://www.w3.org/2000/svg\"/>")
    resources.resolve("nested/fonts").createDirectories()
        .resolve("proof.woff2")
        .writeBytes(byteArrayOf(119, 79, 70, 50))
    resources.resolve("nested/text").createDirectories()
        .resolve("readme.txt")
        .writeText("nested resource")
    resources.resolve("nested/styles").createDirectories()
        .resolve("proof.css")
        .writeText(":root { color: black; }")
    resources.resolve("nested/data").createDirectories()
        .resolve("proof.json")
        .writeText("""{"ready":true}""")
    resources.resolve("nested/images/proof.png").writeBytes(byteArrayOf(1))
    resources.resolve("nested/images/proof.jpg").writeBytes(byteArrayOf(2))
    resources.resolve("nested/images/proof.gif").writeBytes(byteArrayOf(3))
    resources.resolve("nested/images/proof.webp").writeBytes(byteArrayOf(4))
    resources.resolve("nested/fonts/proof.woff").writeBytes(byteArrayOf(5))
    resources.resolve("nested/fonts/proof.ttf").writeBytes(byteArrayOf(6))
    resources.resolve("nested/fonts/proof.otf").writeBytes(byteArrayOf(7))

    block(fixture)
}

private fun Path.readText(): String = Files.readString(this)

private fun sha256ForTest(bytes: ByteArray): String =
    java.security.MessageDigest.getInstance("SHA-256")
        .digest(bytes)
        .joinToString("") { "%02x".format(it) }

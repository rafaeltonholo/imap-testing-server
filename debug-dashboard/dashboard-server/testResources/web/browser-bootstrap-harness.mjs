import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import vm from 'node:vm'

const [bootstrapPath, caseName, entryOverride] = process.argv.slice(2)
assert.ok(bootstrapPath, 'bootstrap path is required')
assert.ok(caseName, 'case name is required')

const source = await fs.readFile(bootstrapPath, 'utf8')
const sandbox = {
    document: {
        currentScript: {
            dataset: {dashboardEntry: '/assets/dashboard-web.mjs'},
        },
    },
}
const context = vm.createContext(sandbox)

const runSetup = (script) => vm.runInContext(script, context)
switch (caseName) {
    case 'safe-empty':
        break
    case 'configurable-preseeds':
        runSetup(`
            Object.defineProperty(globalThis, 'process', {
                value: {release: {name: 'node'}}, configurable: true, writable: true,
            })
            Object.defineProperty(globalThis, 'Deno', {
                value: {}, configurable: true, writable: true,
            })
        `)
        break
    case 'already-safe':
        runSetup(`
            for (const name of ['process', 'Deno']) {
                Object.defineProperty(globalThis, name, {
                    value: undefined,
                    configurable: false,
                    enumerable: false,
                    writable: false,
                })
            }
        `)
        break
    case 'unsafe-process':
        runSetup(`
            Object.defineProperty(globalThis, 'process', {
                value: {release: {name: 'node'}}, configurable: false,
            })
        `)
        break
    case 'unsafe-deno':
        runSetup(`
            Object.defineProperty(globalThis, 'Deno', {
                value: {}, configurable: false,
            })
        `)
        break
    case 'second-verification-failure':
        runSetup(`
            const originalGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor
            let denoReads = 0
            Object.getOwnPropertyDescriptor = (target, name) => {
                const descriptor = originalGetOwnPropertyDescriptor(target, name)
                if (target === globalThis && name === 'Deno' && ++denoReads === 2) {
                    return {...descriptor, writable: true}
                }
                return descriptor
            }
        `)
        break
    case 'import-rejection':
        break
    default:
        if (caseName.startsWith('invalid-entry-')) {
            assert.ok(entryOverride, `${caseName} requires an entry override`)
            sandbox.document.currentScript.dataset.dashboardEntry = entryOverride
        } else {
            throw new Error(`unknown bootstrap harness case: ${caseName}`)
        }
}

let importCalls = 0
let importedSpecifier = null
let completion = 'resolved'
let errorMessage = null
try {
    const result = vm.runInContext(source, context, {
        filename: bootstrapPath,
        importModuleDynamically: async (specifier) => {
            importCalls++
            importedSpecifier = specifier
            if (caseName === 'import-rejection') throw new Error('import rejected by harness')
            return import('data:text/javascript,export default 1')
        },
    })
    await result
} catch (error) {
    completion = 'rejected'
    errorMessage = String(error?.message ?? error)
}

const descriptor = (name) => vm.runInContext(
    `Object.getOwnPropertyDescriptor(globalThis, ${JSON.stringify(name)})`,
    context,
)
const isSafe = (value) =>
    value?.value === undefined &&
    value?.writable === false &&
    value?.enumerable === false &&
    value?.configurable === false

const successCases = new Set(['safe-empty', 'configurable-preseeds', 'already-safe'])
const setupFailureCases = new Set([
    'unsafe-process',
    'unsafe-deno',
    'second-verification-failure',
])

if (successCases.has(caseName)) {
    assert.equal(completion, 'resolved')
    assert.equal(importCalls, 1)
    assert.equal(importedSpecifier, '/assets/dashboard-web.mjs')
    assert.ok(isSafe(descriptor('process')))
    assert.ok(isSafe(descriptor('Deno')))
} else if (caseName === 'import-rejection') {
    assert.equal(completion, 'rejected')
    assert.equal(errorMessage, 'import rejected by harness')
    assert.equal(importCalls, 1)
    assert.ok(isSafe(descriptor('process')))
    assert.ok(isSafe(descriptor('Deno')))
} else if (setupFailureCases.has(caseName) || caseName.startsWith('invalid-entry-')) {
    assert.equal(completion, 'rejected')
    assert.equal(importCalls, 0)
    if (caseName === 'unsafe-deno' || caseName === 'second-verification-failure') {
        assert.ok(isSafe(descriptor('process')))
    }
}

console.log(`PASS ${caseName} imports=${importCalls} completion=${completion}`)

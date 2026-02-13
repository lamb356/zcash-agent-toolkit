/**
 * Lazy WASM initialization singleton.
 *
 * Consumers MUST call `ensureInit()` before using any WASM function.
 * The TypeScript wrapper classes handle this automatically.
 *
 * Supports both browser (fetch-based) and Node.js (fs-based) environments.
 */

let wasmModule: any = null;
let initPromise: Promise<void> | null = null;
let ready = false;

const isNode =
  typeof process !== 'undefined' &&
  process.versions != null &&
  process.versions.node != null;

export async function ensureInit(): Promise<void> {
  if (ready) return;
  if (initPromise) return initPromise;

  initPromise = (async () => {
    const mod = await import('../wasm-pkg/zcash_agent_toolkit_wasm.js');

    if (isNode) {
      // Node.js: read .wasm from disk since fetch() doesn't support file:// URLs
      const { readFileSync } = await import('node:fs');
      const { fileURLToPath } = await import('node:url');
      const { dirname, join } = await import('node:path');
      const thisDir = dirname(fileURLToPath(import.meta.url));
      const wasmPath = join(thisDir, '..', 'wasm-pkg', 'zcash_agent_toolkit_wasm_bg.wasm');
      const wasmBytes = readFileSync(wasmPath);
      mod.initSync({ module: wasmBytes });
    } else {
      await mod.default();
    }

    wasmModule = mod;
    ready = true;
  })();

  return initPromise;
}

export function getWasm(): any {
  if (!ready) {
    throw new Error(
      'WASM not initialized. Call ensureInit() or use a class factory method first.',
    );
  }
  return wasmModule;
}

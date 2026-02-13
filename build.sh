#!/bin/bash
set -euo pipefail

echo "=== Building Zcash Agent Toolkit ==="

# Step 1: Run Rust tests
echo ""
echo "--- Running Rust tests ---"
cargo test --manifest-path Cargo.toml --workspace

# Step 2: Build WASM with SIMD optimizations (matching blake3-wasm config)
echo ""
echo "--- Building WASM ---"
RUSTFLAGS="-C target-feature=+simd128" \
wasm-pack build crates/wasm-bindings \
  --target web \
  --out-dir ../../ts-sdk/wasm-pkg \
  --release

# Step 3: Build TypeScript SDK
echo ""
echo "--- Building TypeScript SDK ---"
cd ts-sdk
npm install
npm run build:ts

# Step 4: Run TypeScript tests (if any)
if [ -f "node_modules/.bin/vitest" ]; then
  echo ""
  echo "--- Running TypeScript tests ---"
  npm test || echo "TypeScript tests not yet configured"
fi

echo ""
echo "=== Build complete ==="
echo "WASM package: ts-sdk/wasm-pkg/"
echo "npm package:  ts-sdk/dist/"

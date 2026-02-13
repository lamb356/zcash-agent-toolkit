$ErrorActionPreference = "Stop"

Write-Host "=== Building Zcash Agent Toolkit ===" -ForegroundColor Cyan

# Step 1: Run Rust tests
Write-Host "`n--- Running Rust tests ---" -ForegroundColor Yellow
cargo test --manifest-path Cargo.toml --workspace

# Step 2: Build WASM
Write-Host "`n--- Building WASM ---" -ForegroundColor Yellow
$env:RUSTFLAGS = "-C target-feature=+simd128"
wasm-pack build crates/wasm-bindings --target web --out-dir ../../ts-sdk/wasm-pkg --release
Remove-Item Env:\RUSTFLAGS

# Step 3: Build TypeScript SDK
Write-Host "`n--- Building TypeScript SDK ---" -ForegroundColor Yellow
Push-Location ts-sdk
npm install
npm run build:ts
Pop-Location

Write-Host "`n=== Build complete ===" -ForegroundColor Green
Write-Host "WASM package: ts-sdk/wasm-pkg/"
Write-Host "npm package:  ts-sdk/dist/"

#!/usr/bin/env bash
set -e

APP_NAME="mediahub"
VERSION="1.0.0"
OUTPUT_DIR="./bin"

mkdir -p "$OUTPUT_DIR"

echo "=== Building MediaHub CLI v${VERSION} ==="

echo "[*] Building local binary..."
go build -ldflags="-s -w -X main.version=${VERSION}" -trimpath -o "${OUTPUT_DIR}/${APP_NAME}" .
echo "[✓] Local build finished: ${OUTPUT_DIR}/${APP_NAME}"

if [ "$1" == "--all" ] || [ "$1" == "all" ]; then
    echo "[*] Cross-compiling for target platforms..."
    
    echo "  -> darwin/arm64..."
    CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -trimpath -o "${OUTPUT_DIR}/${APP_NAME}-${VERSION}-darwin-arm64" .
    echo "  -> darwin/amd64..."
    CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o "${OUTPUT_DIR}/${APP_NAME}-${VERSION}-darwin-amd64" .
    
    echo "  -> linux/amd64..."
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o "${OUTPUT_DIR}/${APP_NAME}-${VERSION}-linux-amd64" .
    echo "  -> linux/arm64..."
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -trimpath -o "${OUTPUT_DIR}/${APP_NAME}-${VERSION}-linux-arm64" .

    echo "  -> windows/amd64..."
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o "${OUTPUT_DIR}/${APP_NAME}-${VERSION}-windows-amd64.exe" .
    echo "  -> windows/arm64..."
    CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -ldflags="-s -w" -trimpath -o "${OUTPUT_DIR}/${APP_NAME}-${VERSION}-windows-arm64.exe" .

    echo "[✓] All platform binaries generated in ${OUTPUT_DIR}/"
fi

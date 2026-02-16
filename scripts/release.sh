#!/bin/bash

set -e

BUMP_TYPE=""
GITHUB_REPO="selcuksarikoz/ssrok"

while [[ $# -gt 0 ]]; do
  case $1 in
    --minor) BUMP_TYPE="minor"; shift ;;
    --major) BUMP_TYPE="major"; shift ;;
    --patch) BUMP_TYPE="patch"; shift ;;
    *) echo "Usage: $0 {--minor|--major|--patch}"; exit 1 ;;
  esac
done

if [ -z "$BUMP_TYPE" ]; then
  echo "Usage: $0 {--minor|--major|--patch}"
  exit 1
fi

CURRENT_VERSION=$(grep "^VERSION :=" Makefile | sed 's/.*= *//')

IFS='.' read -ra VERSION_PARTS <<< "$CURRENT_VERSION"
MAJOR=${VERSION_PARTS[0]}
MINOR=${VERSION_PARTS[1]}
PATCH=${VERSION_PARTS[2]}

case $BUMP_TYPE in
  major) MAJOR=$((MAJOR + 1)); MINOR=0; PATCH=0 ;;
  minor) MINOR=$((MINOR + 1)); PATCH=0 ;;
  patch) PATCH=$((PATCH + 1)) ;;
esac

NEW_VERSION="$MAJOR.$MINOR.$PATCH"

echo "Bumping version: $CURRENT_VERSION → $NEW_VERSION"

sed -i '' "s/^VERSION :=.*/VERSION := $NEW_VERSION/" Makefile
sed -i '' "s/Version = \".*\"/Version = \"$NEW_VERSION\"/" internal/constants/constants.go

echo "Loading configuration from .env.prod..."
if [ -f .env.prod ]; then
  # Load SSROK_SERVER from .env.prod
  SSROK_SERVER_URL=$(grep "^SSROK_SERVER=" .env.prod | cut -d '=' -f2)
  # Remove trailing slash if present
  SSROK_SERVER_URL=${SSROK_SERVER_URL%/}
else
  echo "Error: .env.prod file not found!"
  exit 1
fi

if [ -z "$SSROK_SERVER_URL" ]; then
  echo "Error: SSROK_SERVER not found in .env.prod"
  exit 1
fi

echo "Using Server URL: $SSROK_SERVER_URL"

echo "Building macOS binaries..."

mkdir -p dist

LDFLAGS="-X ssrok/internal/constants.Version=$NEW_VERSION -X ssrok/internal/constants.DefaultServerURL=$SSROK_SERVER_URL -s -w"

GOOS=darwin GOARCH=arm64 go build -ldflags "$LDFLAGS" -o dist/ssrok-darwin-arm64 ./cmd/client
GOOS=darwin GOARCH=amd64 go build -ldflags "$LDFLAGS" -o dist/ssrok-darwin-amd64 ./cmd/client

echo "Building Windows binaries..."
GOOS=windows GOARCH=amd64 go build -ldflags "$LDFLAGS" -o dist/ssrok-windows-amd64.exe ./cmd/client

echo "Building Linux binaries..."
GOOS=linux GOARCH=amd64 go build -ldflags "$LDFLAGS" -o dist/ssrok-linux-amd64 ./cmd/client
GOOS=linux GOARCH=arm64 go build -ldflags "$LDFLAGS" -o dist/ssrok-linux-arm64 ./cmd/client

echo "Calculating SHA256 checksums..."

SHA256_DARWIN_ARM64=$(shasum -a 256 dist/ssrok-darwin-arm64 | awk '{print $1}')
SHA256_DARWIN_AMD64=$(shasum -a 256 dist/ssrok-darwin-amd64 | awk '{print $1}')
SHA256_WINDOWS_AMD64=$(shasum -a 256 dist/ssrok-windows-amd64.exe | awk '{print $1}')
SHA256_LINUX_AMD64=$(shasum -a 256 dist/ssrok-linux-amd64 | awk '{print $1}')
SHA256_LINUX_ARM64=$(shasum -a 256 dist/ssrok-linux-arm64 | awk '{print $1}')

echo "Updating Homebrew formula..."

# Update version and URL
sed -i '' "s|version \".*\"|version \"$NEW_VERSION\"|" Formula/ssrok.rb
sed -i '' 's|github.com/ssrok/ssrok|github.com/selcuksarikoz/ssrok|g' Formula/ssrok.rb
sed -i '' 's|download/v[0-9.]*/|download/v'"$NEW_VERSION"'/|g' Formula/ssrok.rb

# Update SHA256 checksums - macOS arm64 and amd64
sed -i '' '/darwin-arm64/,/sha256/s/sha256 "[a-f0-9]*"/sha256 "'"$SHA256_DARWIN_ARM64"'"/' Formula/ssrok.rb
sed -i '' '/darwin-amd64/,/sha256/s/sha256 "[a-f0-9]*"/sha256 "'"$SHA256_DARWIN_AMD64"'"/' Formula/ssrok.rb

echo "Creating GitHub release..."

if [ -f .env ]; then
  export $(cat .env | grep -v '^#' | xargs)
fi

if [ -z "$GITHUB_TOKEN" ]; then
  echo "Error: GITHUB_TOKEN not set in .env"
  echo "Add GITHUB_TOKEN=your_token to .env file"
  exit 1
fi

export GH_TOKEN="$GITHUB_TOKEN"

if ! command -v gh &> /dev/null; then
  echo "Error: gh CLI not installed"
  exit 1
fi

RELEASE_NOTES="## What's New

- Version $NEW_VERSION released
- macOS ARM64 & AMD64 binaries
- Windows AMD64 binary
- Linux ARM64 & AMD64 binaries
- Homebrew formula updated"

gh release create "v$NEW_VERSION" \
  --title "v$NEW_VERSION" \
  --notes "$RELEASE_NOTES" \
  dist/ssrok-darwin-arm64 \
  dist/ssrok-darwin-amd64 \
  dist/ssrok-windows-amd64.exe \
  dist/ssrok-linux-amd64 \
  dist/ssrok-linux-arm64

echo ""
echo "Pushing Homebrew formula changes..."

echo "Pushing changes..."

git add Makefile internal/constants/constants.go Formula/ssrok.rb
git commit -m "chore: release v$NEW_VERSION"
git push origin HEAD

echo ""
echo "✅ Release v$NEW_VERSION complete!"
echo "   Binary: https://github.com/$GITHUB_REPO/releases/tag/v$NEW_VERSION"
echo "   Brew:   brew upgrade ssrok"

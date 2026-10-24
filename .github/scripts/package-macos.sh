#!/bin/bash
# Package an existing release binary as a Finder-launchable app in a disk image.
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "Usage: $0 BINARY TARGET VERSION OUTPUT_DIRECTORY" >&2
  exit 1
fi

binary="$1"
target="$2"
version="$3"
output="$4"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

case "$target" in
  aarch64-apple-darwin) arch=arm64 ;;
  x86_64-apple-darwin) arch=x86_64 ;;
  *) echo "Unsupported macOS target: $target" >&2; exit 1 ;;
esac

[[ -x "$binary" ]] || { echo "Missing executable: $binary" >&2; exit 1; }
lipo -verify_arch "$arch" "$binary"
# Read the deployment target from the executable, including older Intel headers.
minimum_os="$(vtool -show-build "$binary" | awk '
  $1 == "minos" { print $2; exit }
  $1 == "cmd" && $2 == "LC_VERSION_MIN_MACOSX" { legacy = 1 }
  legacy && $1 == "version" { print $2; exit }
')"
[[ -n "$minimum_os" ]] || { echo "Missing macOS deployment target" >&2; exit 1; }

mkdir -p "$output"
output="$(cd "$output" && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/happy-ip-scanner-app.XXXXXX")"
trap 'rm -rf "$work"' EXIT
stage="$work/image"
app="$stage/Happy IP Scanner.app"
resources="$app/Contents/Resources"
mkdir -p "$app/Contents/MacOS" "$resources" "$work/AppIcon.iconset"
install -m 755 "$binary" "$app/Contents/MacOS/happy-ip-scanner"
cp "$repo_root/"{README.md,LICENSE,CHANGELOG.md,THIRD_PARTY_LICENSES.md} "$resources/"

# Build the native application icon using tools included with macOS.
for size in 16 32 128 256 512; do
  sips -z "$size" "$size" "$repo_root/docs/icon-512.png" \
    --out "$work/AppIcon.iconset/icon_${size}x${size}.png" >/dev/null
  retina=$((size * 2))
  sips -z "$retina" "$retina" "$repo_root/docs/icon-512.png" \
    --out "$work/AppIcon.iconset/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$work/AppIcon.iconset" -o "$resources/AppIcon.icns"

build_version="${version%%-*}"
build_version="${build_version%%+*}"
cat > "$app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key><string>happy-ip-scanner</string>
  <key>CFBundleIdentifier</key><string>io.github.nikhilakki.happy-ip-scanner</string>
  <key>CFBundleName</key><string>Happy IP Scanner</string>
  <key>CFBundleDisplayName</key><string>Happy IP Scanner</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleShortVersionString</key><string>${version}</string>
  <key>CFBundleVersion</key><string>${build_version}</string>
  <key>CFBundleIconFile</key><string>AppIcon.icns</string>
  <key>LSMinimumSystemVersion</key><string>${minimum_os}</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSSupportsAutomaticGraphicsSwitching</key><true/>
  <key>NSLocalNetworkUsageDescription</key><string>Happy IP Scanner discovers hosts and open ports on your local network.</string>
</dict>
</plist>
EOF
plutil -lint "$app/Contents/Info.plist"
# Ad-hoc signing seals the bundle, but does not provide Developer ID notarization.
codesign --force --sign - --timestamp=none "$app"
codesign --verify --deep --strict "$app"

ln -s /Applications "$stage/Applications"
asset="happy-ip-scanner-${version}-${target}.dmg"
hdiutil create -volname "Happy IP Scanner" -srcfolder "$stage" \
  -ov -fs HFS+ -format UDZO "$output/$asset"
hdiutil verify "$output/$asset"
(
  cd "$output"
  shasum -a 256 "$asset" > "$asset.sha256"
)

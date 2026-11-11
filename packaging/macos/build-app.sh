#!/bin/sh
# Usage: build-app.sh VERSION UNIVERSAL_BIN ICNS OUTDIR
set -eu
ver=$1 bin=$2 icns=$3 out=$4
here=$(cd "$(dirname "$0")" && pwd)
app="$out/Ostiary.app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
sed "s/@VERSION@/$ver/g" "$here/Info.plist.in" > "$app/Contents/Info.plist"
cp "$here/Ostiary" "$app/Contents/MacOS/Ostiary"
cp "$bin" "$app/Contents/MacOS/ostiary"
chmod 755 "$app/Contents/MacOS/Ostiary" "$app/Contents/MacOS/ostiary"
cp "$icns" "$app/Contents/Resources/ostiary.icns"
plutil -lint "$app/Contents/Info.plist"
stage=$(mktemp -d)
cp -R "$app" "$stage/"
ln -s /Applications "$stage/Applications"
hdiutil create -volname Ostiary -srcfolder "$stage" -ov -format UDZO "$out/Ostiary-$ver.dmg"
rm -rf "$stage"

# Packaging

Release CI builds all artefacts (see `.github/workflows`). Sources live here.

## Linux .deb (nfpm, pinned v2.48.0)

Needs `build/linux-$ARCH/ostiary` and the brand PNGs copied to `build/icons/<n>.png`
(`internal/brand/png/ostiary-<n>.png`, n = 16 32 48 64 128 256 512).

    GOBIN=/tmp/nfpm-bin go install github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.48.0
    CGO_ENABLED=0 go build -o build/linux-amd64/ostiary .
    mkdir -p build/icons && for n in 16 32 48 64 128 256 512; do cp internal/brand/png/ostiary-$n.png build/icons/$n.png; done
    VERSION=0.0.0-dev ARCH=amd64 /tmp/nfpm-bin/nfpm package -f packaging/linux/nfpm.yaml -p deb -t dist/
    dpkg-deb -I dist/*.deb; dpkg-deb -c dist/*.deb

`ostiary.service` must equal `systemdUnit("/usr/bin/ostiary")`; a test enforces it.

## macOS .app / .dmg (macOS runner only)

    packaging/macos/build-app.sh VERSION UNIVERSAL_BIN ICNS OUTDIR

Writes `OUTDIR/Ostiary.app` and `OUTDIR/Ostiary-VERSION.dmg`. The icns comes from
`go run ./tools/brandgen -out DIR`. Uses `plutil` and `hdiutil`.

## Windows installer (Inno Setup, Windows runner only)

    iscc /DVersion=VERSION /DSrcDir=DIR /DOutDir=DIR packaging\windows\ostiary.iss

`DIR` holds `ostiary.exe`, `ostiary-app.exe` (GUI build) and `ostiary.ico`
(from `tools/brandgen`). Per-user install, no admin. The installer adds the
install dir to the user PATH; uninstall does not remove it (a stale PATH entry
is harmless). `install-service --yes` / `uninstall-service --yes` are honoured
only on Windows, for the installer.

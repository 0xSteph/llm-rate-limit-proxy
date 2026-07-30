#!/bin/sh
# Sluice installer.
#
#   curl -fsSL https://raw.githubusercontent.com/0xSteph/sluice/master/install.sh | sh
#
# Downloads the right binary for this machine, verifies it against the published
# checksums, installs a hardened systemd service, and starts it. Re-running is
# safe: it upgrades in place and leaves your data and config alone.
#
# POSIX sh on purpose — this has to run on a minimal box before anyone has
# installed anything, which is the whole point of a one-line installer.
set -eu

REPO="${SLUICE_REPO:-0xSteph/sluice}"
BIN_DIR="${SLUICE_BIN_DIR:-/usr/local/bin}"
DATA_DIR="${SLUICE_DATA_DIR:-/var/lib/sluice}"
SERVICE_USER="${SLUICE_USER:-sluice}"
PORT="${SLUICE_PORT:-8000}"
# Loopback by default. This process holds every provider key you give it and
# terminates no TLS, so exposing it has to be a deliberate act.
HOST="${SLUICE_HOST:-127.0.0.1}"

say()  { printf '  %s\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
die()  { printf '\n  \033[31m✗\033[0m %s\n\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "need '$1' and it isn't installed"; }

printf '\n  Sluice installer\n\n'

# --- what are we installing onto -------------------------------------------
[ "$(uname -s)" = "Linux" ] || die "this installer is Linux-only; on macOS use Docker"
case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac
ok "linux/$ARCH"

need curl
need tar

# Root is needed to write to /usr/local/bin and manage a service. Ask for it
# explicitly rather than assuming, so piping this to sh as a normal user works.
if [ "$(id -u)" -eq 0 ]; then SUDO=""; else
  command -v sudo >/dev/null 2>&1 || die "not root and 'sudo' isn't available"
  SUDO="sudo"
  say "using sudo for install steps"
fi

# --- private repos need a token, public ones don't --------------------------
AUTH=""
if [ -n "${SLUICE_TOKEN:-${GITHUB_TOKEN:-}}" ]; then
  AUTH="Authorization: Bearer ${SLUICE_TOKEN:-$GITHUB_TOKEN}"
  ok "using a token for a private repository"
fi

api() {
  if [ -n "$AUTH" ]; then curl -fsSL -H "$AUTH" "$@"; else curl -fsSL "$@"; fi
}

# --- find the newest release ------------------------------------------------
VERSION="${SLUICE_VERSION:-}"
if [ -z "$VERSION" ]; then
  say "looking up the latest release..."
  VERSION=$(api "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null \
    | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1) || true
  [ -n "$VERSION" ] || die "no published release found.
     If the repository is private, set a token:
       SLUICE_TOKEN=ghp_... curl -fsSL .../install.sh | sh
     If nothing is released yet, cut one:
       git tag v0.1.0 && git push origin v0.1.0"
fi
ok "installing $VERSION"

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT INT TERM
V="${VERSION#v}"
TARBALL="sluice-${V}-linux-${ARCH}.tar.gz"

# Private releases cannot be fetched from the browser URL, so go through the
# API, which honours the token.
fetch_asset() {
  name="$1"; out="$2"
  if [ -n "$AUTH" ]; then
    # A private release asset can only be fetched through the API, and only with
    # the octet-stream Accept header — the browser_download_url 404s. Whitespace
    # is stripped first so the match does not depend on GitHub's JSON spacing.
    url=$(api "https://api.github.com/repos/$REPO/releases/tags/$VERSION" \
      | tr -d ' \n' | tr '{' '\n' \
      | grep "\"name\":\"$name\"" \
      | sed -n 's/.*"url":"\([^"]*\)".*/\1/p' | head -1)
    [ -n "$url" ] || die "release $VERSION has no asset named $name"
    curl -fsSL -H "$AUTH" -H "Accept: application/octet-stream" "$url" -o "$out"
  else
    curl -fsSL "https://github.com/$REPO/releases/download/$VERSION/$name" -o "$out"
  fi
}

say "downloading $TARBALL"
fetch_asset "$TARBALL" "$TMP/$TARBALL" || die "download failed"
fetch_asset "SHA256SUMS" "$TMP/SHA256SUMS" || die "could not fetch checksums"

# --- verify before trusting --------------------------------------------------
if command -v sha256sum >/dev/null 2>&1; then
  ( cd "$TMP" && sha256sum -c SHA256SUMS --ignore-missing >/dev/null 2>&1 ) \
    || die "checksum mismatch — refusing to install"
  ok "checksum verified"
else
  say "sha256sum not present; skipping verification"
fi

tar -xzf "$TMP/$TARBALL" -C "$TMP"
[ -f "$TMP/sluice-$ARCH" ] || die "archive did not contain the expected binary"

# --- install -----------------------------------------------------------------
$SUDO install -m 0755 "$TMP/sluice-$ARCH" "$BIN_DIR/sluice"
ok "installed $BIN_DIR/sluice"

# An unprivileged service account with no shell and no home to log into.
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  $SUDO useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER" \
    2>/dev/null || $SUDO adduser --system --no-create-home --shell /sbin/nologin "$SERVICE_USER"
  ok "created service user '$SERVICE_USER'"
fi

$SUDO mkdir -p "$DATA_DIR"
$SUDO chown "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR"
$SUDO chmod 0700 "$DATA_DIR"
ok "data directory $DATA_DIR"

# --- service -----------------------------------------------------------------
if command -v systemctl >/dev/null 2>&1; then
  $SUDO tee /etc/systemd/system/sluice.service >/dev/null <<UNIT
[Unit]
Description=Sluice — rate-limit-aware LLM API proxy
Documentation=https://github.com/$REPO
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
Environment=DATA_DIR=$DATA_DIR
Environment=HOST=$HOST
Environment=PORT=$PORT
ExecStart=$BIN_DIR/sluice
Restart=on-failure
RestartSec=3

# It holds every provider key you give it, so it gets nothing it doesn't need.
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
ReadWritePaths=$DATA_DIR
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
UNIT
  $SUDO systemctl daemon-reload
  $SUDO systemctl enable --now sluice >/dev/null 2>&1 || $SUDO systemctl restart sluice
  ok "service started and enabled at boot"

  # Wait for it to answer rather than claiming success and hoping.
  i=0
  while [ $i -lt 20 ]; do
    if curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
      ok "responding on port $PORT"
      break
    fi
    i=$((i + 1)); sleep 0.5
  done
  [ $i -lt 20 ] || die "installed, but it did not come up. Check: journalctl -u sluice -n 50"
  MANAGED=1
else
  MANAGED=0
fi

# Tell the truth about the machine we are actually on: printing systemctl hints
# to a box with no systemd, or "open this URL" for something not yet running,
# is how an installer teaches people not to read its output.
if [ "$MANAGED" = "1" ]; then
  cat <<DONE

  Done. Open http://localhost:$PORT and finish the setup wizard —
  the first visitor becomes the admin, so do that now.

    status    systemctl status sluice
    logs      journalctl -u sluice -f
    upgrade   re-run this installer
    remove    sudo systemctl disable --now sluice \
                && sudo rm $BIN_DIR/sluice /etc/systemd/system/sluice.service

DONE
else
  cat <<DONE

  Installed, but this system has no systemd, so nothing is running yet.
  Start it with:

    sudo -u $SERVICE_USER DATA_DIR=$DATA_DIR HOST=$HOST PORT=$PORT $BIN_DIR/sluice

  Then open http://localhost:$PORT and finish the setup wizard —
  the first visitor becomes the admin.

    upgrade   re-run this installer
    remove    sudo rm $BIN_DIR/sluice

DONE
fi

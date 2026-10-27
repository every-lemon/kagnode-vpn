#!/usr/bin/env bash
# VPN self-contained updater. Upstream scripts retain their own licenses.
set -Eeuo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
VERSION=@@UPDATE_VERSION@@
if [[ ${1:-} == --plain ]]; then export VPN_STACK_PLAIN=1; shift; fi
case ${1:-} in
  --help|-h)
    printf 'VPN updater %s\nUsage: sudo bash update.sh [--plain] [--prerelease]\n       bash update.sh --verify\nUpdates VPN application code only; Ubuntu security updates run separately.\nArchives itself under /var/lib/vpn/updates/update-VERSION.sh after success.\nVPN 4 clients, administrators, MFA and engine configuration are preserved.\n' "$VERSION"
    exit 0 ;;
  ''|--verify|--prerelease) ;;
  *) printf 'Unknown option. Use --help.\n' >&2; exit 2 ;;
esac
command -v python3 >/dev/null || { printf 'Python 3 is required on the installed VPN server.\n' >&2; exit 1; }
exec python3 - "${BASH_SOURCE[0]}" "$@" 3<&0 <<'VPN_STACK_UPDATER_PY'
@@UPDATER_RUNTIME@@
VPN_STACK_UPDATER_PY
# END_VPN_STACK_UPDATER

#!/bin/bash
# Install or update an Enclave-network provider on a Linux server with a public IPv4 address
# (docs/design/enclave-network.md, docs/network/open-participation.md). Run as root ON the server, from a directory
# holding wg-provider.mjs. Nobody's approval, name reservation or fleet secret is needed: the operator key is made here,
# and every authority the provider trusts or asks is named on this command line.
#
#   bash install.sh <release> <region> --checkers 0x..[,0x..] --rpc https://a --rpc https://b \
#        --directory https://dir1 [--directory https://dir2 ...] --pins authority-pins.json \
#        --zone <app zone> --probe-zone <probe zone> [--roles guard,ingress,egress] [--public-address A.B.C.D] \
#        [--uplink eth0] [--relay https://domain-map-origin] [--config-only]
#   --pins     {"deployments","registry","connectivity","sessionVaultFactory"} addresses (network/network-authorities.mjs);
#              zero disables connectivity (paid service) or session-vault owners. No mutable address book is read.
#   --relay    optional, ONLY the custom-domain map source; without it the provider serves app-zone names alone.
#   --config-only  write and check provider.json (and the operator key) and stop: no packages, firewall or service.
#   ENCLAVE_NETWORK_ROOT=<dir> prefixes /etc, /var/lib and /opt (a staging tree; default: the real ones).
#
# Enclave's own fleet keeps its previous form, as an explicit opt-in to Enclave's defaults (relay fallback, the mutable
# address book, app.enclave.host / probe.enclave.host):
#   bash install.sh <release> <region> <checker-address[,checker-address...]> [roles] --legacy-enclave-defaults
#
# Idempotent: keys and state are kept across updates; the previous release stays for rollback
# (/opt/enclave-network/previous). Fields the operator manages in provider.json (kind, hostId, pricePerGiB6,
# proofKeyFile, localRoutes, noSniRoute, budget, ports) are kept on update. It does not touch any other service or
# firewall table, and it publishes nothing anywhere: advertising in a service index is a separate, explicit step.
set -euo pipefail
usage() { sed -n '2,26p' "$0" >&2; exit 2; }
[ $# -ge 3 ] || usage
REL=$1 REGION=$2; shift 2
LEGACY=0 CHECKER="" ROLES="guard,ingress,egress" PINS="" ZONE="" PROBE_ZONE="" PUBLIC="" UPLINK="eth0" RELAY="" CONFIG_ONLY=0; RPCS=(); DIRS=()
R=${ENCLAVE_NETWORK_ROOT:-}; ETC=$R/etc/enclave-network VAR=$R/var/lib/enclave-network OPT=$R/opt/enclave-network
if [[ "${1:-}" != --* ]]; then CHECKER=$1; shift; if [[ "${1:-}" != --* && -n "${1:-}" ]]; then ROLES=$1; shift; fi; LEGACY=-1; fi
while [ $# -gt 0 ]; do
  case "$1" in
    --legacy-enclave-defaults) LEGACY=1; shift ;;
    --checkers) CHECKER=${2:?}; shift 2 ;;
    --roles) ROLES=${2:?}; shift 2 ;;
    --rpc) RPCS+=("${2:?}"); shift 2 ;;
    --directory) DIRS+=("${2:?}"); shift 2 ;;
    --pins) PINS=${2:?}; shift 2 ;;
    --zone) ZONE=${2:?}; shift 2 ;;
    --probe-zone) PROBE_ZONE=${2:?}; shift 2 ;;
    --public-address) PUBLIC=${2:?}; shift 2 ;;
    --uplink) UPLINK=${2:?}; shift 2 ;;
    --relay) RELAY=${2:?}; shift 2 ;;
    --config-only) CONFIG_ONLY=1; shift ;;
    *) usage ;;
  esac
done
[ $LEGACY = -1 ] && { echo "the positional form uses Enclave's defaults: add --legacy-enclave-defaults to choose them, or name your own authorities (--rpc --directory --pins --zone --probe-zone)" >&2; exit 2; }
[[ $REL =~ ^[a-z0-9.-]+$ && $REGION =~ ^[a-z0-9-]+$ && $CHECKER =~ ^0x[0-9a-fA-F]{40}(,0x[0-9a-fA-F]{40})*$ && $ROLES =~ ^[a-z]+(,[a-z]+)*$ && $UPLINK =~ ^[a-zA-Z0-9_.-]+$ ]] || usage
if [ $LEGACY = 0 ]; then
  [ ${#RPCS[@]} -ge 2 ] && [ ${#DIRS[@]} -ge 1 ] && [ -n "$PINS" ] && [ -n "$ZONE" ] && [ -n "$PROBE_ZONE" ] || {
    echo "name your own authorities: two or more --rpc, one or more --directory, --pins, --zone and --probe-zone (or --legacy-enclave-defaults)" >&2; exit 2; }
  [ -s "$PINS" ] || { echo "--pins $PINS: no such file" >&2; exit 2; }
fi
HERE=$(cd "$(dirname "$0")" && pwd)
[ $CONFIG_ONLY = 1 ] || command -v wg >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -q wireguard-tools >/dev/null
NODE=$(command -v node); "$NODE" -e 'process.exit(+process.versions.node.split(".")[0]>=22?0:1)' || { echo "node 22+ required" >&2; exit 1; }
install -d -m 0700 "$ETC" "$VAR"
# the operator key is made here and never leaves this server
if [ ! -s "$ETC/operator.key" ]; then (umask 077; printf '0x%s\n' "$(openssl rand -hex 32)" > "$ETC/operator.key"); fi
chmod 0600 "$ETC/operator.key"
if [ -z "$PUBLIC" ]; then
  PUBLIC=$(curl -s -m 5 http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address || true)
  [[ $PUBLIC =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || PUBLIC=$(ip -4 -o addr show dev "$UPLINK" scope global | awk '{print $4}' | cut -d/ -f1 | grep -vE '^(10|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.' | head -1)
fi
[[ $PUBLIC =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "no public IPv4 address found (pass --public-address)" >&2; exit 1; }

# provider.json: the bootstrap from this command line; the operator-managed fields of an existing config kept as they are
CFG=$ETC/provider.json
ETC=$ETC VAR=$VAR LEGACY=$LEGACY PUBLIC=$PUBLIC UPLINK=$UPLINK ROLES=$ROLES REGION=$REGION CHECKER=$CHECKER PINS=$PINS ZONE=$ZONE PROBE_ZONE=$PROBE_ZONE RELAY=$RELAY \
RPCS="$(IFS=,; echo "${RPCS[*]-}")" DIRS="$(IFS=,; echo "${DIRS[*]-}")" "$NODE" -e '
  const fs = require("fs"), e = process.env, list = (s) => (s ? s.split(",") : []);
  let old = {}; try { old = JSON.parse(fs.readFileSync(process.argv[1], "utf8")); } catch {}
  const kept = Object.fromEntries(["kind","hostId","pricePerGiB6","proofKeyFile","localRoutes","noSniRoute","budget","ports"].filter((k) => k in old).map((k) => [k, old[k]]));
  const base = { operatorKeyFile: e.ETC + "/operator.key", publicAddress: e.PUBLIC, uplink: e.UPLINK, roles: list(e.ROLES), pricePerGiB6: 0,
    region: e.REGION, kind: "enclave", hostId: null, ports: { exit: 51820, guard: 51821, control: 51822 }, checkers: list(e.CHECKER.toLowerCase()),
    stateDir: e.VAR, budget: { monthlyBytes: 1000000000000, stopAt: 850000000000 } };
  const boot = e.LEGACY === "1"
    ? { rpc: ["https://mainnet.base.org","https://base-rpc.publicnode.com","https://base.drpc.org"], addressBook: "0xab214342d5A490150A4A977063A2f88E21F80907",
        relay: "https://api.enclave.host", zone: "app.enclave.host", probeZone: "probe.enclave.host",
        ...(old.directories ? { directories: old.directories } : {}), ...(old.authorityPins ? { authorityPins: old.authorityPins } : {}) }
    : { bootstrap: "explicit", rpc: list(e.RPCS), directories: list(e.DIRS), authorityPins: JSON.parse(fs.readFileSync(e.PINS, "utf8")),
        zone: e.ZONE, probeZone: e.PROBE_ZONE, ...(e.RELAY ? { relay: e.RELAY } : {}) };
  fs.writeFileSync(process.argv[1] + ".new", JSON.stringify({ ...base, ...kept, ...boot }, null, 1) + "\n", { mode: 0o600 });' "$CFG"
install -d -m 0755 "$OPT/$REL"
install -m 0644 "$HERE/wg-provider.mjs" "$OPT/$REL/wg-provider.mjs"
# the release about to run checks the configuration before anything is switched
"$NODE" "$OPT/$REL/wg-provider.mjs" --check-config "$CFG.new" || { echo "provider.json rejected; nothing changed" >&2; rm -f "$CFG.new"; exit 1; }
chmod 0600 "$CFG.new" && mv "$CFG.new" "$CFG"
if [ $CONFIG_ONLY = 1 ]; then echo "configured $CFG (--config-only: no packages, firewall or service changed)"; exit 0; fi
# forwarding, and the ports the provider serves (ufw stays in charge of everything else)
printf 'net.ipv4.ip_forward=1\n' > /etc/sysctl.d/90-enclave-network.conf && sysctl -q -p /etc/sysctl.d/90-enclave-network.conf
for r in 51820/udp 51821/udp 51822/tcp 443/tcp 80/tcp; do ufw allow "$r" >/dev/null; done
ufw route allow in on wg-exit out on "$UPLINK" >/dev/null
ufw route allow in on wg-guard out on "$UPLINK" >/dev/null
cat > /etc/systemd/system/enclave-network-provider.service <<EOF
[Unit]
Description=Enclave network provider (WireGuard guard/ingress/egress)
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=$NODE $OPT/current/wg-provider.mjs $CFG
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
# switch releases atomically; keep the one being replaced
if [ -L "$OPT/current" ] && [ "$(readlink "$OPT/current")" != "$OPT/$REL" ]; then ln -sfn "$(readlink "$OPT/current")" "$OPT/previous"; fi
ln -sfn "$OPT/$REL" "$OPT/current"
systemctl daemon-reload && systemctl enable -q enclave-network-provider && systemctl restart enclave-network-provider
sleep 4; systemctl is-active enclave-network-provider
journalctl -u enclave-network-provider -n 50 --no-pager | grep -o 'provider [0-9a-f]\{32\} up.*' | tail -1
echo "installed; nothing was advertised. To list this provider's services in a service index, see docs/network/open-participation.md"

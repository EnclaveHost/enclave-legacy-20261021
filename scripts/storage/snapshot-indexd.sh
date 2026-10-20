#!/usr/bin/env bash
# Run as root on the source. A bounded maintenance stop makes PostgreSQL and
# Bolt consensus belong to the same quiescent indexd instance. No live Bolt copy.
# The output is PRIVATE recovery material and must be encrypted before transport.
set -euo pipefail
umask 077
out=${1:?usage: snapshot-indexd.sh NEW_PRIVATE_DIRECTORY}
[[ "$out" = /* && ! -e "$out" ]] || { echo 'absolute, new output directory required' >&2; exit 2; }
[[ $(id -u) = 0 ]] || { echo 'root required' >&2; exit 2; }
source_config=${SNAPSHOT_INDEXD_CONFIG:-/etc/indexd/indexd.yml}
source_data=${SNAPSHOT_INDEXD_DATA:-/var/lib/indexd}
source_binary=${SNAPSHOT_INDEXD_BINARY:-/opt/indexd/current/indexd}
systemctl is-active --quiet indexd
for p in "$source_config" "$source_data/consensus.db" "$source_binary"; do test -f "$p"; done
command -v pg_dump >/dev/null
command -v python3 >/dev/null
# Refuse a target with less than two GiB free; the current chain is about 500 MB.
parent=$(dirname "$out")
test -d "$parent"
available_bytes=$(df -PB1 "$parent" | awk 'NR==2 {print $4}')
[[ "$available_bytes" -ge 2147483648 ]] || { echo 'insufficient snapshot space' >&2; exit 2; }
mkdir -m 0700 "$out"
restart_needed=0
cleanup() {
  rc=$?
  trap - EXIT HUP INT TERM
  if [[ "$restart_needed" = 1 ]]; then systemctl start indexd || rc=1; fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
started=$(date +%s)
restart_needed=1
systemctl stop indexd
# Do not take a snapshot if the source writer is still alive.
[[ $(systemctl show indexd --property=MainPID --value) = 0 ]]
runuser -u postgres -- pg_dump --format=custom --no-owner --no-acl indexd > "$out/indexd.pgdump"
cp --reflink=auto "$source_data/consensus.db" "$out/consensus.db"
cp "$source_config" "$out/indexd.yml"
cp "$source_binary" "$out/indexd"
if [[ -f "$source_data/GeoLite2-City.mmdb" ]]; then cp "$source_data/GeoLite2-City.mmdb" "$out/GeoLite2-City.mmdb"; fi
runuser -u postgres -- psql --dbname=indexd --tuples-only --no-align --quiet -c "SELECT json_build_object('objects',(SELECT count(*) FROM objects),'slabs',(SELECT count(*) FROM slabs),'contracts',(SELECT count(*) FROM contracts),'accounts',(SELECT count(*) FROM accounts));" > "$out/counts.json"
systemctl start indexd
systemctl is-active --quiet indexd
restart_needed=0
resumed=$(date +%s)
# Hash only after the service has resumed. No database/config contents are printed.
python3 - "$out" "$started" "$resumed" <<'PY'
import datetime,hashlib,json,sys
from pathlib import Path
p=Path(sys.argv[1]);files={}
names=['indexd.pgdump','consensus.db','indexd.yml','indexd','counts.json']
if (p/'GeoLite2-City.mmdb').exists():names.append('GeoLite2-City.mmdb')
for name in names:
 f=p/name;h=hashlib.sha256()
 with f.open('rb') as stream:
  for part in iter(lambda:stream.read(1024*1024),b''):h.update(part)
 files[name]={'bytes':f.stat().st_size,'sha256':h.hexdigest()}
report={'capturedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'quiesced':True,'stopThroughStartSeconds':int(sys.argv[3])-int(sys.argv[2]),'sourceResumed':True,'files':files,'counts':json.loads((p/'counts.json').read_text())}
(p/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
PY

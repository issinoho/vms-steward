#!/usr/bin/env bash
# push.sh <node> - upload the source tree to <node>'s work directory, keeping its
# directory structure (vms.sh put is flat). Only what the VMS build needs: src/,
# tests/unit/, www/, vms/ and build_vms.com.
set -euo pipefail
top=$(cd "$(dirname "$0")/.." && pwd)
node=${1:?usage: push.sh <node>}
read -r _ _ HOST PORT USER _ SFTPDIR _ < <(awk -v n="$node" '$1==n' "$top/tools/nodes.conf")
key=${VMS_SSH_KEY:-$HOME/.ssh/vms_ed25519}
cd "$top"
files=$(git ls-files src tests/unit www vms build_vms.com 2>/dev/null; git ls-files --others --exclude-standard src tests/unit www vms build_vms.com 2>/dev/null)
{
    echo "cd $SFTPDIR"
    for d in $(printf '%s\n' $files | xargs -n1 dirname | sort -u); do
        [ "$d" = . ] && continue
        p=""
        IFS=/ read -ra parts <<< "$d"
        for part in "${parts[@]}"; do p="${p:+$p/}$part"; echo "-mkdir $p"; done
    done | awk '!seen[$0]++'
    for f in $files; do echo "put $f $f"; done
} | sftp -P "$PORT" -i "$key" -o BatchMode=yes -b - "$USER@$HOST" 2>&1 | grep -vE '^sftp>|Welcome|^ *$' || true
echo "push: $(printf '%s\n' $files | wc -l) files -> $node"

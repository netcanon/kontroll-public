#!/bin/sh
# C10 origin-push defence-in-depth (dogfood VM 144, 2026-07-05). Installed at <canonical>/hooks/update by
# ansible/playbooks/local-canonical.yml. The network service (uid 1001) may ONLY stage refs/heads/proposed/* — it
# must NEVER receive-pack-update main. The legit mirror push (local-canonical.yml "Mirror" task) runs as uid 0
# (installer container, docker/services/installer.yaml user "0:0") or the operator uid (host-direct run), NEVER
# 1001 -> allowed. A human/Semaphore promote uses `git update-ref` (NOT receive-pack), so this hook never fires for
# it (constraint C2). This is the belt to gitio.commit_and_push's `and not staging` code guard (the boundary).
# Keyed on the UNSPOOFABLE real uid (`id -u`) — no env override a uid-1001 caller could set. SECURITY.md C10.
#
# argv (git `update` hook): $1 = refname, $2 = old-sha, $3 = new-sha. A non-zero exit rejects that ref's update.
if [ "$1" = "refs/heads/main" ] && [ "$(id -u)" = "1001" ]; then
    echo "C10: uid 1001 may only stage refs/heads/proposed/* — refusing a direct main push." >&2
    echo "     (propose-then-promote: a human/Semaphore promotes via kontroll-promote.)" >&2
    exit 1
fi
exit 0

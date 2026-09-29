#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

hook_input=${1:?Usage: test-snap-install-hook.sh <install-hook> [gateway-binary]}
hook_dir=$(cd "$(dirname "$hook_input")" && pwd)
hook="${hook_dir}/$(basename "$hook_input")"
work=$(mktemp -d "${TMPDIR:-/tmp}/openshell snap install hook.XXXXXX")
trap 'rm -rf "$work"' EXIT

export SNAP="${work}/snap"
mkdir -p "$SNAP/bin"
if [[ -n ${2:-} ]]; then
  ln -s "$(realpath "$2")" "$SNAP/bin/openshell-gateway"
else
  cat >"$SNAP/bin/openshell-gateway" <<'STUB'
#!/bin/sh
set -eu
[ "$#" -eq 4 ] && [ "$1" = config ] && [ "$2" = migrate-mtls ] && [ "$3" = --path ]
[ -f "$4" ] && [ "${MIGRATION_FAIL:-0}" = 0 ]
cat "$MIGRATED_CONFIG"
STUB
  chmod 755 "$SNAP/bin/openshell-gateway"
fi
export MIGRATED_CONFIG="${work}/migrated.toml"
expect_migration() {
  sed -e 's/allow_unauthenticated_users = true/allow_unauthenticated_users = false/' \
      -e 's/disable_tls = true/disable_tls = false/' "$common/gateway.toml" >"$MIGRATED_CONFIG"
}

expected="${work}/expected.toml"
cat >"$expected" <<'EOF'
[openshell]
version = 2

[openshell.gateway]
EOF

legacy="${work}/legacy.toml"
cat >"$legacy" <<'EOF'
[openshell]
version = 2

[openshell.gateway]

[openshell.gateway.auth]
allow_unauthenticated_users = true
EOF

common="${work}/fresh"
SNAP_COMMON="$common" "$hook"
cmp -s "$expected" "$common/gateway.toml"
if [[ -z $(find "$common/gateway.toml" -perm 600) ]]; then
  echo "FAIL: install hook config must be mode 0600" >&2
  exit 1
fi

printf '\nallow_driver_config = true\n' >>"$common/gateway.toml"
cp "$common/gateway.toml" "${work}/operator-before"
cp "$common/gateway.toml" "$MIGRATED_CONFIG"
SNAP_COMMON="$common" "$hook"
cmp -s "${work}/operator-before" "$common/gateway.toml"

common="${work}/legacy"
mkdir -p "$common"
cp "$legacy" "$common/gateway.toml"
chmod 644 "$common/gateway.toml"
expect_migration
SNAP_COMMON="$common" "$hook"
if ! cmp -s "$MIGRATED_CONFIG" "$common/gateway.toml"; then
  echo "FAIL: install hook must migrate the legacy unauthenticated config" >&2
  exit 1
fi
if [[ -z $(find "$common/gateway.toml" -perm 600) ]]; then
  echo "FAIL: migrated config must be mode 0600" >&2
  exit 1
fi

common="${work}/legacy-edited"
mkdir -p "$common"
cp "$legacy" "$common/gateway.toml"
printf '\n# operator note\n' >>"$common/gateway.toml"
cp "$common/gateway.toml" "${work}/legacy-edited-before"
expect_migration
SNAP_COMMON="$common" "$hook"
cmp -s "$MIGRATED_CONFIG" "$common/gateway.toml"

common="${work}/custom-insecure"
mkdir -p "$common"
cat >"$common/gateway.toml" <<'EOF'
[openshell]
version = 2

[openshell.gateway]
compute_driver = "docker"
allow_driver_config = true
disable_tls = true # old local override

[openshell.gateway.auth]
allow_unauthenticated_users = true # old local override
EOF
cp "$common/gateway.toml" "${work}/custom-insecure-before"
expect_migration
SNAP_COMMON="$common" "$hook"
cmp -s "$MIGRATED_CONFIG" "$common/gateway.toml"

before_inode=$(stat -c %i "$common/gateway.toml")
expect_migration
SNAP_COMMON="$common" "$hook"
[[ $(stat -c %i "$common/gateway.toml") == "$before_inode" ]]

common="${work}/custom-secure"
mkdir -p "$common"
cat >"$common/gateway.toml" <<'EOF'
[openshell]
version = 2

[openshell.gateway]
compute_driver = "docker"
# allow_unauthenticated_users = true
EOF
cp "$common/gateway.toml" "${work}/custom-secure-before"
cp "$common/gateway.toml" "$MIGRATED_CONFIG"
SNAP_COMMON="$common" "$hook"
cmp -s "${work}/custom-secure-before" "$common/gateway.toml"

common="${work}/post-refresh"
mkdir -p "$common" "${work}/snap/meta/hooks"
cp "$hook" "${work}/snap/meta/hooks/install"
cp "${work}/legacy-edited-before" "$common/gateway.toml"
expect_migration
mkdir -p "${work}/bin"
cat >"${work}/bin/snapctl" <<EOF
#!/bin/sh
printf '%s\\n' "\$*" >>"${work}/snapctl.log"
EOF
chmod 755 "${work}/bin/snapctl"
PATH="${work}/bin:$PATH" SNAP="${work}/snap" SNAP_COMMON="$common" \
  SNAP_INSTANCE_NAME=openshell "${hook_dir}/post-refresh"
if ! cmp -s "$MIGRATED_CONFIG" "$common/gateway.toml"; then
  echo "FAIL: post-refresh hook must migrate an edited insecure config" >&2
  exit 1
fi
if [[ $(cat "${work}/snapctl.log") != "restart openshell.gateway" ]]; then
  echo "FAIL: post-refresh hook must restart the gateway" >&2
  cat "${work}/snapctl.log" >&2
  exit 1
fi

common="${work}/invalid"
mkdir -p "$common"
printf '[openshell.gateway\ndisable_tls = true\n' >"$common/gateway.toml"
cp "$common/gateway.toml" "${work}/invalid-before"
if MIGRATION_FAIL=1 SNAP_COMMON="$common" "$hook"; then
  echo "FAIL: invalid TOML migration must fail" >&2
  exit 1
fi
cmp -s "${work}/invalid-before" "$common/gateway.toml"
if [[ -n $(find "$common" -name 'gateway.toml.tmp.*') ]]; then
  echo "FAIL: failed migration left temporary files" >&2
  exit 1
fi

common="${work}/broken-link"
mkdir -p "$common"
ln -s "${work}/missing-target" "$common/gateway.toml"
SNAP_COMMON="$common" "$hook"
if [[ $(readlink "$common/gateway.toml") != "${work}/missing-target" ]]; then
  echo "FAIL: install hook replaced a broken operator symlink" >&2
  exit 1
fi

common="${work}/directory"
mkdir -p "$common/gateway.toml"
SNAP_COMMON="$common" "$hook"
if [[ ! -d "$common/gateway.toml" ]]; then
  echo "FAIL: install hook replaced an operator-owned directory" >&2
  exit 1
fi

if [[ -n $(find "$work" -name 'gateway.toml.pre-mtls*') ]]; then
  echo "FAIL: install hook must not keep copies of replaced configs" >&2
  exit 1
fi

echo "Snap install hook tests passed"

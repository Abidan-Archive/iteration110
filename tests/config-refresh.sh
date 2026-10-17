#!/usr/bin/env bash
set -euo pipefail
umask 077

root="$(git rev-parse --show-toplevel)"
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
mkdir -p "$temporary/releases/one/bootstrap/cache"
cp "$root/tests/fixtures/config-cache-artisan.php" "$temporary/releases/one/artisan"
ln -s "$temporary/releases/one" "$temporary/current"
printf '%s\n' 'APP_KEY=synthetic-test-value' > "$temporary/environment"
printf '%s\n' "<?php return ['fixture' => 'original'];" > "$temporary/releases/one/bootstrap/cache/config.php"

export ABIDAN_CURRENT_RELEASE="$temporary/current"
export ABIDAN_ENV_FILE="$temporary/environment"
export ABIDAN_PHP="$(command -v php)"
export ABIDAN_LOCK_FILE="$temporary/lock"

bash "$root/scripts/refresh-laravel-config.sh"
test "$(readlink "$temporary/releases/one/.env")" = "$temporary/environment"
"$ABIDAN_PHP" -r 'exit((require $argv[1])["fixture"] === "refreshed" ? 0 : 1);' \
  "$temporary/releases/one/bootstrap/cache/config.php"
test "$(stat -c %a "$temporary/releases/one/bootstrap/cache/config.php")" = '640'

before="$(sha256sum "$temporary/releases/one/bootstrap/cache/config.php")"
export FAIL_CONFIG_REFRESH=1
if bash "$root/scripts/refresh-laravel-config.sh"; then
  printf '%s\n' 'Failed cache rebuild incorrectly succeeded.' >&2
  exit 1
fi
test "$before" = "$(sha256sum "$temporary/releases/one/bootstrap/cache/config.php")"
unset FAIL_CONFIG_REFRESH

export ABIDAN_ENV_FILE="$temporary/missing-environment"
if bash "$root/scripts/refresh-laravel-config.sh"; then
  printf '%s\n' 'Missing managed environment incorrectly succeeded.' >&2
  exit 1
fi
test "$before" = "$(sha256sum "$temporary/releases/one/bootstrap/cache/config.php")"

export ABIDAN_CURRENT_RELEASE="$temporary/not-deployed"
bash "$root/scripts/refresh-laravel-config.sh"
printf '%s\n' 'Passed refresh checks: managed env link, protected cache, atomic failure, missing env, and initial provisioning.'

set -euo pipefail
umask 077

# The systemd unit runs this entire script as the application user. Serialize
# overlapping deploy/secret refresh requests without executing Artisan as root.
exec 9>"$ABIDAN_LOCK_FILE"
flock -x 9

release="$(readlink -e "$ABIDAN_CURRENT_RELEASE" || true)"
if [[ -z "$release" || ! -f "$release/artisan" ]]; then
  printf '%s\n' 'No active Laravel release; skipping configuration refresh.'
  exit 0
fi

if [[ -n "$ABIDAN_ENV_FILE" ]]; then
  test -r "$ABIDAN_ENV_FILE"
  ln -sfn "$ABIDAN_ENV_FILE" "$release/.env"
fi

cache_dir="$release/bootstrap/cache"
mkdir -p "$cache_dir"
test -w "$cache_dir"
temporary_dir="$(mktemp -d "$cache_dir/.config-refresh.XXXXXX")"
trap 'rm -rf "$temporary_dir"' EXIT

cd "$release"
# config:cache normally clears config.php first. Redirect it to a separate,
# initially nonexistent path, so failures leave the active cache intact.
env APP_CONFIG_CACHE="$temporary_dir/config.php" \
  "$ABIDAN_PHP" artisan config:cache --no-interaction
test -s "$temporary_dir/config.php"
chmod 0640 "$temporary_dir/config.php"
mv -f "$temporary_dir/config.php" "$cache_dir/config.php"

printf '%s\n' 'Laravel configuration cache refreshed.'
# systemd runs the unit's fixed ExecStartPost operations only after success.

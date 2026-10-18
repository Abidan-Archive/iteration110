# Laravel 13 and restricted deployment rollout

## Prepared changes

The application now targets Laravel 13 / PHP 8.3, Node 24, Inertia 2, and Vite 8.
GitHub tests the application and builds both client and SSR bundles before uploading
an allow-listed artifact. SSH/SCP use a pinned host key. Third-party Actions are
pinned to commit SHAs; remote execution uses OpenSSH rather than an SSH action.

`telariel` remains the host administrator and Nix trusted user. The separate
`abidan-deploy` account belongs only to `abidan`, has restricted public-key SSH,
and may run exactly this privileged command:

```sh
sudo -n /run/current-system/sw/bin/systemctl restart abidan-config-refresh.service
```

It necessarily has application-level access (code, runtime environment, deployment
migrations), but no wheel membership, Nix trust, age identity, or general sudo.
The application service user can write storage and bootstrap caches, but cannot
replace deployer-owned application code or the `current` release link.

## Prerequisites for the actual rollout

These code changes can be reviewed first. Before activating the host or pushing
the new workflow to `prod`, complete the separate production-environment step:

1. Publish `secrets/production.env` in the application repository and advance
   `abidan-environment` to a revision containing it.
2. Add `MEDIAWIKI_OAUTH_CLIENT_SECRET` to `secrets.yaml` through SOPS and verify
   the application and MediaWiki use the same value.
3. Preserve the existing `APP_KEY`, issuer URLs, and signing key.
4. Perform a normal full NixOS build with SOPS validation enabled. The currently
   pinned missing file / missing encrypted key intentionally remain blockers until
   that follow-on step is completed.

The administrator's age key stays at
`/home/telariel/.config/sops/age/keys.txt`; do not copy it to the deployment account.

## 1. Create a dedicated deployment key

On your trusted workstation, create a key used only by GitHub Actions. For an
unattended deployment the workflow expects a key without a passphrase:

```sh
ssh-keygen -t ed25519 -f ~/.ssh/abidan-actions -C abidan-github-actions
```

Add only its public `.pub` line to `deploymentAuthorizedKeys` in `settings.nix`:

```nix
deploymentAuthorizedKeys = [
  "ssh-ed25519 REPLACE_WITH_THE_PUBLIC_KEY abidan-github-actions"
];
```

The list ships empty, so no new identity is authorized until you supply your key.
`modules/users.nix` automatically prefixes these keys with OpenSSH's `restrict`.

## Local verification

The targeted module check does not require production decryption or bypass SOPS
validation; it checks only the deployment identity, privilege rules, and services:

```sh
nix eval --impure --json --expr \
  'import ./tests/deployment.nix { inputs = (builtins.getFlake (toString ./.)).inputs; }'
nix shell nixpkgs#php83 --command bash tests/config-refresh.sh
nix shell nixpkgs#python3 nixpkgs#mariadb --command python tests/mysql-passwords.py
```

## 2. Build and apply the host

After completing the environment prerequisites, build and apply the configuration
using your usual administrator deployment method:

```sh
nix build .#nixosConfigurations.abidan.config.system.build.toplevel --no-link
```

The host creates `abidan-deploy` and creates new release/artifact containers under
that identity. The top-level application directory is root-owned with the sticky
bit: group members may create entries but cannot replace each other's entries.
Directory-setup services run as the application/deployment users, never as root.
As the administrator, migrate existing release/artifact ownership once
(pause deployments while doing this):

```sh
base=/srv/http/abidanarchive.com
sudo chown -R --no-dereference abidan-deploy:abidan "$base/releases" "$base/artifacts"
sudo chmod 2755 "$base/releases"
sudo chmod 2750 "$base/artifacts"
if test -L "$base/current"; then
  sudo chown --no-dereference abidan-deploy:abidan "$base/current"
fi
sudo chmod -R g-w "$base/releases"
sudo find "$base/releases" -type d -exec chmod 2755 {} +
sudo find "$base/releases" -type d -path '*/bootstrap/cache' -exec chmod 2770 {} +
sudo find "$base/releases" -type f -path '*/bootstrap/cache/*.php' -exec chmod 0660 {} +
```

Changing the existing `current` symlink's owner is required: the sticky parent
otherwise prevents the new deployment user from replacing the old user's link.

Shared storage remains owned by `abidan:abidan`. Ensure its directories are
group-writable if migrating from a different layout. Existing releases must
already link `.env` to `/etc/abidan/runtime.env`.
The refresh service recognizes the existing link and does not require write access
to the release's top-level directory.

## 3. Configure GitHub Actions

In the application repository, open **Settings → Secrets and variables → Actions**.

### Repository secrets

| Name | Value |
| --- | --- |
| `HOST_USER` | `abidan-deploy` |
| `HOST_KEY` | Complete contents of the dedicated private `~/.ssh/abidan-actions` key |
| `HOST_KNOWN_HOSTS` | A verified known_hosts line matching `HOST_IP` |

Obtain the server's public host key through your existing trusted administrative
connection or Linode console:

```sh
sudo cat /etc/ssh/ssh_host_ed25519_key.pub
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

For example, if `HOST_IP` is `203.0.113.10`, the secret must look like:

```text
203.0.113.10 ssh-ed25519 REPLACE_WITH_THE_SERVER_PUBLIC_HOST_KEY
```

Use the server's host public key, not the deployment user's public key. If using
`ssh-keyscan` to format the line, verify its fingerprint against the trusted server
output before saving it. The workflow deliberately does not trust a fresh scan.

### Repository variables

| Name | Expected value |
| --- | --- |
| `HOST_IP` | Server IPv4 address or DNS hostname (SSH port 22) |
| `DATA_DIR` | `/srv/http/abidanarchive.com` |
| `PHPFPM_USER` | `abidan` |
| `DOMAIN` | `abidanarchive.com` |

No sudo password, age key, or plaintext application environment belongs in GitHub.
After a successful deployment using the new identity, remove the old deployment
private key from GitHub and retire that credential wherever else it was used.

## 4. Verify access and deploy

From the workstation, verify the restricted identity:

```sh
ssh -T -i ~/.ssh/abidan-actions abidan-deploy@HOST 'id; sudo -n -l'
ssh -T -i ~/.ssh/abidan-actions abidan-deploy@HOST \
  'test -r /etc/abidan/runtime.env && test -w /srv/http/abidanarchive.com/releases'
```

Expect the `abidan` supplementary group, no wheel group, and only the fixed service
restart under passwordless sudo.

### Manual maintenance window for the cache-format transition

Enter maintenance mode on the outgoing application before applying hardening
changes or activating Laravel 13. Pre-render the maintenance response so incoming
web requests do not boot the old application and repopulate its caches:

```sh
base=/srv/http/abidanarchive.com
sudo -u abidan php "$base/current/artisan" down --render='errors::503' --retry=60
```

Finish the host/ownership preparation above while maintenance remains enabled.
Once that preparation is complete, let in-flight requests finish, stop the old
queue worker, and clear the application cache using the **outgoing** release:

```sh
sudo systemctl stop laravel-queue-worker.service
sudo -u abidan php "$base/current/artisan" cache:clear
```

This removes old serialized permission/tag collections before the new release
boots. The keys remain `permissions` and `tagNames`; no versioned replacement keys
are introduced. After clearing, do not run further outgoing-release Artisan
commands, restart the old worker, or rebuild the host against the old release:
those operations can repopulate the old payloads. Proceed directly to deployment.

Push the tested application/workflow to `prod`, or run **Deploy Application**
manually with `prod` selected. The deployment script does not enter or leave this
maintenance window automatically. Its existing cache clear during preparation
can remain; the manual clear above is the one required before the first new boot.

The remote script (`abidan/bin/deploy-release`) prepares a new release, runs
migrations and builds caches, switches `current` atomically, and requests the
host-owned configuration refresh. Deployments are serialized by GitHub concurrency
and a host-side flock. Three recent releases/artifacts are retained.

Check the site, password and Discord login, wiki SSO, report submission, search,
audio scrub/playback, and queue processing. Inspect these without printing secrets:

```sh
systemctl status abidan-config-refresh phpfpm-abidan laravel-queue-worker --no-pager
journalctl -u abidan-config-refresh --since '10 minutes ago'
readlink -f /srv/http/abidanarchive.com/current
```

After verifying the upgraded release and successful configuration refresh, start
the queue worker and leave maintenance mode using the new active release:

```sh
sudo systemctl start laravel-queue-worker.service
sudo -u abidan php /srv/http/abidanarchive.com/current/artisan up
```

The stopped queue worker needs this explicit start because the refresh unit uses
`try-restart`, which does not start an inactive service. If deployment fails,
keep maintenance enabled while resolving the failure.

If activation/refresh fails, inspect the failed step before retrying. A failed
preparation can leave a release directory named after the commit; remove that
failed directory as the deployment user before rerunning the same commit. Never
remove the active release. The script refuses to overwrite an existing release.

## Rollback

Choose a retained, compatible release, atomically repoint `current`, then request
the same config refresh. Run application Artisan commands as `abidan`, never root.
For a rollback across this cache-format transition, re-enter pre-rendered
maintenance, stop workers, and clear cache with the currently active upgraded
release **before** switching back. This prevents the old code from reading the
new scalar-array payloads. Restart workers and run `up` only after the older
release's configuration refresh succeeds.
Database migrations run before activation and are not automatically rolled back;
confirm schema compatibility before selecting an older release. Do not use
`migrate:rollback` blindly on production.

The upgrade keeps the previous session-cookie name and PHP session serialization,
filesystem root, and cache prefix. Permission/tag caches use scalar arrays under
the existing keys; the manual maintenance-window clear removes old Eloquent
objects before the transition. Keep `APP_KEY`
unchanged so existing encrypted data and cookies remain readable.

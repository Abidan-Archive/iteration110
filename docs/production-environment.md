# Laravel production environment and automatic refresh

NixOS owns production variable updates. SOPS decrypts at **activation**, not build
time, and its rendered environment triggers `abidan-config-refresh.service` when
it changes. Rebuilding the host after changing the pinned encrypted environment
is sufficient: no application deployment or manual cache command is needed for a
variable-only update.

The service runs Artisan as `abidan`, serializes refresh requests, builds a new
configuration cache outside the active `config.php`, and atomically replaces it
only after success. The cache has mode `0640`. Fixed, privileged `ExecStartPost`
commands reload PHP-FPM and restart the queue only after a successful build. No
mutable application code runs as root.

Deployments link `.env` to `/etc/abidan/runtime.env`, which points to the SOPS-rendered
`/run/secrets/rendered/abidan.env`. The SSH deployment user belongs to the `abidan`
group and can read this `0440` file and prepare release/cache directories. Deployment
contains no sudo password. Its only elevated action is the narrowly permitted:

```sh
sudo -n /run/current-system/sw/bin/systemctl restart abidan-config-refresh.service
```

New application releases need this refresh because each has its own Laravel cache.
For secret/variable-only changes SOPS triggers the same service automatically.

## Migration

This host now enables the managed environment and pins `Abidan-Archive/archive`'s
`prod` branch. The workflow requires `/etc/abidan/runtime.env`; the old Laravel
decryption fallback and host `ENV_KEY` declaration have been removed.

For the first rollout, **publish the encrypted environment to `prod` first without
the new workflow**, update the host pin and deploy NixOS, and only then publish the
new workflow/application changes. This avoids a deployment trying to use the managed
environment before the server has it. The current remote pin predates the migration;
it must advance once the encrypted file has been pushed.

### 1. Preserve the existing environment

Use the existing production environment, including the **exact current `APP_KEY`**.
Do not run `key:generate` or change credentials as part of this migration.

From the application repository in its development shell, decrypt the existing
`.env.prod.encrypted` into a private temporary directory, not the repository. Laravel
will prompt for its current environment-decryption key without printing it:

```sh
umask 077
temporary="$(mktemp -d)"
APP_ENV=deployment php artisan env:decrypt --env=prod \
  --path "$temporary" --filename production.env
```

If the active server environment has changes absent from `.env.prod.encrypted`, use
that authoritative environment instead. The migration must preserve those values.
Keep the temporary file only as long as needed for encryption and comparison.

### 2. Encrypt the entire file with SOPS

Use the **public age recipient(s)** authorized for the server's existing age private
key, plus any maintenance recipients you want. Public recipients may be committed;
private age keys remain outside Git and GitHub Actions.

Use SOPS's native dotenv format for readable editing: each variable stays on its
own line and each value is encrypted individually. Quotes, literal `$` characters,
and interpolation remain in the values. Blank lines are normalized away. This
format expects one variable per physical line.

```sh
mkdir -p secrets
AGE_RECIPIENTS='age1REPLACE_WITH_AUTHORIZED_PUBLIC_RECIPIENT'
sops --config /dev/null --encrypt --input-type dotenv --output-type dotenv \
  --age "${AGE_RECIPIENTS:?Set AGE_RECIPIENTS to the public age recipient(s)}" \
  --output secrets/production.env \
  "${temporary:?Set temporary to the plaintext temporary directory}/production.env"
test -s secrets/production.env
```

`--config /dev/null` bypasses inherited `.sops.yaml` creation rules for this initial
encryption. SOPS can otherwise reject the temporary input filename before using
explicit recipients. All options must precede the input filename. `--output` writes
the destination only after encryption succeeds, unlike shell redirection, which
can truncate an existing destination even on failure.
The `--encrypt` form also works on older SOPS versions that do not recognize the
`encrypt` subcommand. The shell's `:?` checks prevent empty recipient/path variables
from silently reaching SOPS. The later subcommand examples assume the current SOPS
provided by the updated development environment.

An authorized local key can verify preservation of all parsed variable values
without displaying plaintext (formatting/blank lines may differ):

```sh
sops --decrypt --input-type dotenv --output-type dotenv \
  --output "$temporary/roundtrip.env" secrets/production.env
php -r '
  require "vendor/autoload.php";
  $before = Dotenv\Dotenv::parse(file_get_contents($argv[1]));
  $after = Dotenv\Dotenv::parse(file_get_contents($argv[2]));
  if ($before !== $after) {
    fwrite(STDERR, "Environment values changed during conversion.\n");
    exit(1);
  }
  print("Environment values preserved.\n");
' "$temporary/production.env" "$temporary/roundtrip.env"
rm -rf -- "$temporary"
unset temporary
```

Commit **only** `secrets/production.env` to the application's production branch.
The workflow excludes `secrets/` and plaintext `.env` files from application artifacts.
Do not commit the temporary plaintext or any private age key.

### 3. Pin the encrypted file in the host configuration

The input is configured inside `iteration110/flake.nix`'s existing `inputs` block:

```nix
abidan-environment = {
  url = "github:Abidan-Archive/archive/prod";
  flake = false;
};
```

For a private repository, use an authenticated Git reference supported by the
machine building the host (e.g. `git+ssh://git@github.com/OWNER/REPOSITORY?ref=prod`).
The builder needs access to the encrypted repository; it does not need the age
decryption key.

`configuration.nix` now receives `inputs` and enables the environment:

```nix
services.abidan.environment = {
  enable = true;
  sopsFile = "${inputs.abidan-environment}/secrets/production.env";
};
```

Update only that input and build with normal SOPS validation enabled:

```sh
nix flake update abidan-environment
nix build .#nixosConfigurations.abidan.config.system.build.toplevel --no-link
```

The host appends its canonical URLs, OIDC file paths, `APP_ENV=production`, and
`APP_DEBUG=false` to the preserved dotenv content. Those host-managed values take
precedence. All other production values remain from the encrypted file.

### 4. Prepare permissions on the currently active release once

New deployments prepare these permissions automatically. Before the first managed
environment activation, prepare the existing release on the server if needed:

```sh
release="$(readlink -f /srv/http/abidanarchive.com/current)"
sudo chgrp abidan "$release"
sudo chmod g+rwx "$release"
sudo chgrp -R abidan "$release/bootstrap/cache"
sudo chmod -R g+rwX "$release/bootstrap/cache"
```

This is a one-time administrator operation, not a password supplied by CI. Ensure
GitHub's `HOST_USER` is the configured deployer (`abidan-deploy`) and belongs to `abidan`;
the narrow sudo rule is issued to that user.

### 5. Rebuild the host and verify

Apply the host configuration using your normal remote rebuild command. SOPS writes
the runtime environment and requests the cache refresh automatically:

```sh
systemctl status abidan-config-refresh.service --no-pager
journalctl -u abidan-config-refresh.service --since '10 minutes ago'
systemctl status phpfpm-abidan laravel-queue-worker --no-pager
```

A successful oneshot normally becomes inactive; use its exit status and journal to
check success. Test the Archive, login, queue processing, mail, and wiki SSO. Verify
`.env` is a symlink and the cached configuration has restricted permissions without
printing either file's contents.

After successful verification, retire `.env.prod.encrypted` and the unused encrypted
`ENV_KEY` entry as a separate cleanup. Neither secret file was edited by the wiring
changes; the old host declaration and deployment fallback are already removed.

## Future updates

Edit the encrypted environment in the **application repository**:

```sh
sops --config /dev/null --input-type dotenv --output-type dotenv secrets/production.env
```

Commit the encrypted change, then update its host input and rebuild NixOS:

```sh
nix flake update abidan-environment
# Run your usual NixOS deploy command.
```

SOPS detects the rendered-file change and refreshes Laravel automatically. Updating
the application repository alone does not advance the host's pinned input. Database
or search-service credential rotation still requires updating the corresponding
service credentials; this migration only changes how Laravel's environment is stored.

If refresh fails, the previous configuration cache is retained and workers are not
reloaded. Correct the environment/service connectivity issue and retry the fixed
refresh unit. Laravel service providers may require database/Redis access during
`config:cache`, so these services must be available.

## Converting an existing binary environment

If you already created `secrets/production.env.json`, decrypt it to a private
temporary dotenv file first, without printing its contents:

```sh
umask 077
temporary="$(mktemp -d)"
sops --decrypt --input-type binary --output-type binary \
  --output "$temporary/production.env" secrets/production.env.json
```

Then follow step 2 to encrypt as native dotenv and verify the values, and select
the new `secrets/production.env` path in NixOS. Delete the old `.json` file after
verification; the host consumes only native dotenv and needs no compatibility flag.

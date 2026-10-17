# Abidan username synchronization

`AbidanOpenIDConnect` wraps the standard OpenIDConnect authentication plugin.
After a successful login finds an existing wiki user by the stable issuer/subject
mapping, it synchronizes that user's name with the verified `preferred_username`
claim. New accounts use the upstream extension's normal creation flow.

The rename runs before PluggableAuth reloads the user and finishes authentication.
MediaWiki's core rename service retains the wiki user ID and OIDC mapping, updates
contribution attribution, and moves user/user-talk pages with redirects when the
user has permission to move them. Core also invalidates older wiki sessions.

Synchronization happens on the next OIDC login, not while an existing wiki session
is browsing. Names follow MediaWiki's normal capitalization and underscore/space
normalization. If a requested name is invalid or already taken, the existing name
is kept and login continues; this is retried on subsequent logins. Details are
logged to the `AbidanUsernameSync` debug log group. Other rename/page-move errors
are logged too; partial page-move failures do not undo a completed account rename.

No `renameuser` permission is granted to ordinary wiki users. The trusted provider
can only rename the account already identified by a successful OIDC login.

## Wiki roles

The NixOS MediaWiki configuration also uses PluggableAuth's built-in `mapped`
group synchronization with Archive's verified `wiki_roles` claim:

- `wiki_admin` maps to `sysop` (standard MediaWiki administrator rights).
- `wiki_moderator` maps to `moderator` (block/blockemail, delete/undelete,
  deletedhistory/deletedtext, protect, rollback, patrol/autopatrol).

Assignments are managed through Archive's ACL user-management interface. Archive
`admin`/`mod` roles do not implicitly map to wiki groups. Both additions and removals
take effect on the next wiki login, including initial account creation; active
sessions are not updated in the background. Missing or empty claims remove managed
groups, while unrelated local groups are preserved. Bureaucrat `userrights` is
disabled so privileged role assignment stays in Archive.

## Integration checks

From the Nix configuration repository, build the package and install a disposable
SQLite wiki. This checks real account/actor renames, preserved OIDC links and edit
ownership, user/talk page moves and redirects, canonical spelling, invalid names,
collisions, repeated renames, plugin registration, and the authentication adapter.
It also checks real OIDC group mapping, administrator/moderator grants and removals,
missing/empty claims, unrelated groups, moderator rights, and first-login grants.

```sh
wiki="$(nix build .#nixosConfigurations.abidan.config.services.mediawiki.finalPackage --no-link --print-out-paths)/share/mediawiki"
php="$(nix build .#nixosConfigurations.abidan.config.services.mediawiki.phpPackage --no-link --print-out-paths)/bin/php"
testdir="$(mktemp -d)"
"$php" "$wiki/maintenance/run.php" install \
  --dbtype sqlite --dbpath "$testdir" --dbname username_sync_test \
  --confpath "$testdir" --server http://wiki.localhost --scriptpath /w \
  --pass 'Disposable-test-password-4931!' \
  --extensions PluggableAuth,OpenIDConnect 'Username Sync Test' TestAdmin
MW_INSTALL_PATH="$wiki" MW_TEST_SETTINGS="$testdir/LocalSettings.php" \
  "$php" "$wiki/maintenance/run.php" \
  "$wiki/extensions/AbidanUsernameSync/tests/usernameSync.php" \
  --conf "$wiki/extensions/AbidanUsernameSync/tests/LocalSettings.php"
```

The test runner only accepts a SQLite wiki named `username_sync_test`.

{config, pkgs, ...}: let
  inherit (import ../settings.nix {inherit pkgs;}) app administrator;
in {
  sops = {
    defaultSopsFile = ../secrets.yaml;
    defaultSopsFormat = "yaml";
    age.keyFile = "/home/${administrator}/.config/sops/age/keys.txt";

    secrets = {
      DB_PW = {};
      MEILISEARCH_KEY = {restartUnits = ["meilisearch.service"];};
      ACME_KEY = {mode = "0440"; group = "acme";};
      LONGVIEW_KEY = {};
      LONGVIEW_DB_PW = {};
      ABIDAN_OIDC_PRIVATE_KEY = {
        owner = app;
        group = app;
        mode = "0400";
        restartUnits = ["phpfpm-${app}.service" "laravel-queue-worker.service"];
      };
      MEDIAWIKI_INIT_ADMIN_PW = {
        owner = "mediawiki";
        group = config.users.users.mediawiki.group;
        mode = "0400";
      };
      MEDIAWIKI_OAUTH_CLIENT_SECRET = {
        owner = "mediawiki";
        group = config.users.users.mediawiki.group;
        mode = "0400";
        restartUnits = ["phpfpm-mediawiki.service"];
      };
    };
    templates = {
      # Same secret as the wiki, rendered separately for Laravel's service user.
      ABIDAN_OAUTH_CLIENT_SECRET = {
        content = config.sops.placeholder.MEDIAWIKI_OAUTH_CLIENT_SECRET;
        owner = app;
        group = app;
        mode = "0400";
        restartUnits = ["phpfpm-${app}.service" "laravel-queue-worker.service"];
      };
    };
  };
}

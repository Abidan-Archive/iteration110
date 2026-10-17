{config, lib, pkgs, ...}: let
  inherit (import ../settings.nix {inherit pkgs;}) app domain wikiDomain srv hostDir dataDir phpPackage;
  cfg = config.services.abidan.environment;
  oidcEnvironment = {
    APP_URL = "https://${domain}";
    OAUTH_PRIVATE_KEY_PATH = config.sops.secrets.ABIDAN_OIDC_PRIVATE_KEY.path;
    OAUTH_CLIENT_MEDIAWIKI_SECRET_FILE = config.sops.templates.ABIDAN_OAUTH_CLIENT_SECRET.path;
    MEDIAWIKI_URL = "https://${wikiDomain}";
    MEDIAWIKI_REDIRECT_URI = "https://${wikiDomain}/wiki/Special:PluggableAuthLogin";
  };
  runtimeEnvironment = oidcEnvironment // lib.optionalAttrs cfg.enable {
    APP_ENV = "production";
    APP_DEBUG = "false";
  };
  environmentText = lib.concatStringsSep "\n" (lib.mapAttrsToList (name: value: "${name}=${value}") runtimeEnvironment) + "\n";
  refreshConfig = pkgs.writeShellApplication {
    name = "abidan-config-refresh";
    runtimeInputs = [pkgs.coreutils pkgs.util-linux pkgs.systemd];
    text = builtins.readFile ../scripts/refresh-laravel-config.sh;
  };
in {
  options.services.abidan.environment = {
    enable = lib.mkEnableOption "SOPS-managed Laravel production environment";
    sopsFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "SOPS-encrypted production environment, usually from a pinned application-repository input.";
    };
  };

  config = {
    assertions = [{
      assertion = !cfg.enable || cfg.sopsFile != null;
      message = "Set services.abidan.environment.sopsFile before enabling the managed Laravel environment.";
    }];

    environment.systemPackages = with pkgs; [
      redis
      phpPackage
      php83Packages.composer
      nodejs_22
      ffmpeg
      audiowaveform
    ];

    environment.etc."abidan/runtime.env" = lib.mkIf cfg.enable {
      source = config.sops.templates."abidan.env".path;
    };
    sops.secrets.ABIDAN_PRODUCTION_ENV = lib.mkIf cfg.enable {
      sopsFile = cfg.sopsFile;
      format = "dotenv";
      key = "";
    };
    sops.templates."abidan.env" = lib.mkIf cfg.enable {
      # Preserve dotenv quoting/interpolation; append host-owned settings last.
      content = config.sops.placeholder.ABIDAN_PRODUCTION_ENV + "\n" + environmentText;
      owner = app;
      group = app;
      mode = "0440";
      restartUnits = ["abidan-config-refresh.service"];
    };

    systemd.services.abidan-config-refresh = {
      description = "Atomically refresh Laravel configuration and reload application services";
      wantedBy = lib.optional cfg.enable "multi-user.target";
      wants = ["mysql.service" "redis-${app}.service"];
      after = [
        "mysql.service" "mysql-set-passwords.service" "redis-${app}.service"
        "sops-install-secrets.service" "setup-srv-directories.service"
        "phpfpm-${app}.service" "laravel-queue-worker.service"
      ];
      environment = runtimeEnvironment // {
        ABIDAN_CURRENT_RELEASE = "${dataDir}/current";
        ABIDAN_ENV_FILE = lib.optionalString cfg.enable "/etc/abidan/runtime.env";
        ABIDAN_PHP = "${phpPackage}/bin/php";
        ABIDAN_LOCK_FILE = "/run/abidan-config-refresh/lock";
      };
      unitConfig.ConditionPathExists = "${dataDir}/current/artisan";
      serviceConfig = {
        Type = "oneshot";
        User = app;
        Group = app;
        UMask = "0077";
        RuntimeDirectory = "abidan-config-refresh";
        RuntimeDirectoryMode = "0700";
        ExecStart = lib.getExe refreshConfig;
        # Only these fixed systemd operations run with elevated privileges; the
        # application and its mutable Artisan entrypoint run as the service user.
        ExecStartPost = [
          "+${pkgs.systemd}/bin/systemctl try-reload-or-restart --no-block phpfpm-${app}.service"
          "+${pkgs.systemd}/bin/systemctl try-restart --no-block laravel-queue-worker.service"
        ];
      };
    };

    systemd.services.setup-srv-directories = {
      description = "Create directories for rolling release web files";
      wantedBy = ["multi-user.target"];
      script = ''
        mkdir -p ${hostDir}
        chmod 755 ${srv}
        chmod 755 ${hostDir}
        mkdir -p ${dataDir}/{artifacts,releases,storage}
        mkdir -p ${dataDir}/storage/{app,framework,logs}
        mkdir -p ${dataDir}/storage/app/public
        mkdir -p ${dataDir}/storage/framework/{cache,sessions,views}
        chmod 775 ${dataDir}
        chmod 775 ${dataDir}/artifacts
        chmod 775 ${dataDir}/releases
        chmod -R 775 ${dataDir}/storage
        # Preserve SSH ownership of release/artifact files across reboots so
        # deployment and retention cleanup do not require root.
        chown ${app}:${app} ${hostDir} ${dataDir} ${dataDir}/artifacts ${dataDir}/releases
        chown -R ${app}:${app} ${dataDir}/storage
      '';
      serviceConfig = {Type = "oneshot"; RemainAfterExit = true; User = "root";};
    };

    services.phpfpm = {
      inherit phpPackage;
      pools.${app} = {
        user = app;
        phpEnv = runtimeEnvironment;
        settings = {
          "listen.owner" = app;
          "pm" = "ondemand";
          "pm.max_children" = 10;
          "pm.start_servers" = 2;
          "pm.min_spare_servers" = 1;
          "pm.max_spare_servers" = 3;
          "pm.process_idle_timeout" = "10s";
          "pm.max_requests" = 500;
          "security.limit_extensions" = ".php";
          "php_admin_value[disable_functions]" = "exec,passthru,shell_exec,system";
          "php_admin_flag[allow_url_fopen]" = "off";
          "php_admin_value[upload_max_filesize]" = "100M";
          "php_admin_value[post_max_size]" = "102M";
          "php_admin_value[memory_limit]" = "256M";
        };
      };
    };

    systemd.services.laravel-queue-worker = {
      description = "Laravel Queue Worker";
      after = ["network.target"];
      wantedBy = ["multi-user.target"];
      environment = runtimeEnvironment;
      serviceConfig = {
        User = app;
        Group = app;
        Restart = "always";
        RestartSec = "10s";
        ExecStart = "${phpPackage}/bin/php ${dataDir}/current/artisan queue:work --sleep=3 --tries=3 --max-time=3600";
        WorkingDirectory = "${dataDir}/current";
      };
    };
  };
}

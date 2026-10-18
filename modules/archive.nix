{config, lib, pkgs, ...}: let
  inherit (import ../settings.nix {inherit pkgs;}) app domain wikiDomain hostDir dataDir phpPackage deployer;
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
      nodejs_24
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

    # Root manages only root-owned containers. Never recursively chmod/chown
    # a deployment-writable tree from a privileged service.
    systemd.tmpfiles.rules = [
      "d ${hostDir} 0755 root root - -"
      "d ${dataDir} 1775 root ${app} - -"
    ];

    systemd.services.setup-srv-directories = {
      description = "Create application-owned shared storage";
      wantedBy = ["multi-user.target"];
      after = ["systemd-tmpfiles-setup.service"];
      script = ''
        umask 0002
        mkdir -p ${dataDir}/storage/{app,framework,logs}
        mkdir -p ${dataDir}/storage/app/public
        mkdir -p ${dataDir}/storage/framework/{cache,sessions,views}
        # Deploy-time Artisan and the application user share runtime files.
        # Inherit the application group instead of the deployer's primary group.
        chmod g+s ${dataDir}/storage \
          ${dataDir}/storage/{app,framework,logs} \
          ${dataDir}/storage/app/public \
          ${dataDir}/storage/framework/{cache,sessions,views}
      '';
      serviceConfig = {Type = "oneshot"; RemainAfterExit = true; User = app; Group = app;};
    };

    systemd.services.setup-deployment-directories = {
      description = "Create deployer-owned release and artifact containers";
      wantedBy = ["multi-user.target"];
      after = ["systemd-tmpfiles-setup.service"];
      script = ''
        umask 0027
        mkdir -p ${dataDir}/{artifacts,releases}
        # Existing containers are migrated once by the administrator.
        if test -O ${dataDir}/releases; then chmod 2755 ${dataDir}/releases; fi
        if test -O ${dataDir}/artifacts; then chmod 2750 ${dataDir}/artifacts; fi
      '';
      serviceConfig = {Type = "oneshot"; RemainAfterExit = true; User = deployer; Group = app;};
    };

    services.phpfpm = {
      inherit phpPackage;
      pools.${app} = {
        user = app;
        # FPM's INI parser treats an unquoted `false` as an empty value.
        phpEnv = lib.mapAttrs (_: value: "\"${value}\"") runtimeEnvironment;
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

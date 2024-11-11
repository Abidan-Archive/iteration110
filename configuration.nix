{
  pkgs,
  inputs,
  config,
  ...
}: let
  MAINTAINER_EMAIL = "hey@manning390.com";
  USER = "HOST_USER";
  app = "abidan";
  domain = "next.abidanarchive.com";
  srv = "/srv";
  hostDir = "${srv}/http";
  dataDir = "${hostDir}/${domain}";
in {
  imports = [
    # Include the results of the hardware scan.
    ./hardware-configuration.nix
  ];

  # Use the GRUB 2 boot loader.
  boot.loader.grub.enable = true;

  nix.settings.experimental-features = ["nix-command" "flakes"];

  # For some reason on this nixos system on linode vm dns queries over ipv6 fail
  # lego, the ACME software, refuses to make a flag to force ipv4 and strong prefers ipv6
  # unless can solve why ipv6 fails, turning it off entirely and forcing ipv4 is best option
  networking.enableIPv6 = false;
  networking.usePredictableInterfaceNames = false; # Linode: Linode guides assume eth0
  networking.useDHCP = false; # Linode: Disable DHCP globally, will not need it
  networking.interfaces.eth0.useDHCP = true; # Linode: Required for ssh?
  # Open ports in the firewall.
  networking.firewall.allowedTCPPorts = [80 443];
  networking.nameservers = [
    "8.8.8.8"
    "1.1.1.1"
    # "2001:4860:4860::8888" # No need when ipv6 is off
    # "2001:4860:4860::8844" # No need when ipv6 is off
  ];

  # Linode region is Atlanta
  time.timeZone = "America/New_York";

  # User setup
  users = {
    users = {
      # User for SSH access
      ${USER} = {
        isNormalUser = true;
        extraGroups = ["wheel" "networkmanager" "nginx" app];
        openssh.authorizedKeys.keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHJbtlS3h7escz5e1Jgdgc4ZHfH4adAxNq9AwXPWw0+a ${USER}"];
      };
      # User for phpfpm systemd process
      ${app} = {
        group = app;
        isSystemUser = true;
      };
      # Allow nginx to access SSL certificates
      "nginx".extraGroups = ["acme" app];
    };
    # Ensure phpfpm and nginx group exist
    groups = {
      ${app} = {};
      "nginx" = {};
    };
  };

  # Secret management
  sops = {
    defaultSopsFile = ./secrets.yaml;
    defaultSopsFormat = "yaml";
    age.keyFile = "/home/${USER}/.config/sops/age/keys.txt";
    secrets = {
      ENV_KEY = {
        mode = "0440";
        group = app;
      };
      DB_PW = {};
      MEILISEARCH_KEY = {};
      ACME_KEY = {
        mode = "0440";
        group = "acme";
      };
      LONGVIEW_KEY = {};
      LONGVIEW_DB_PW = {};
    };
    templates = {
      "MEILISEARCH_KEY_FILE".content = "MEILI_MASTER_KEY=${config.sops.placeholder.MEILISEARCH_KEY}";
    };
  };

  # List packages installed in system profile. To search, run:
  # $ nix search wget
  environment.systemPackages = with pkgs; [
    vim # Do not forget to add an editor to edit configuration.nix! The Nano editor is also installed by default.
    wget
    inetutils # Linode: used by support
    mtr # Linode: used by support
    sysstat # Linode: used by linode support
    git
    (php83.buildEnv {
      extensions = {
        enabled,
        all,
      }:
        enabled
        ++ (with all; [
          ctype
          curl
          dom
          fileinfo
          mbstring
          openssl
          pdo
          session
          tokenizer
          xml
          redis
        ]);
      extraConfig = ''
      '';
    })
    php83Packages.composer
    ffmpeg # Required by app for audio snips
    audiowaveform # Required by app for generating waveform .dats
  ];

  # Some programs need SUID wrappers, can be configured further or are
  # started in user sessions.
  programs.mtr.enable = true; # Linode: used by linode support

  # Services
  # Enable the OpenSSH daemon.
  services.openssh = {
    enable = true;
    settings.PasswordAuthentication = false;
    settings.KbdInteractiveAuthentication = false;
    settings.PermitRootLogin = "no";
  };

  # SSL certificate renawl settings
  # /var/lib/acme.challenges must be writable by the ACME user
  # and readable by the nginx user.
  security.acme = {
    acceptTerms = true;
    defaults = {
      email = MAINTAINER_EMAIL;
      # enableDebugLogs = true;
      dnsResolver = "1.1.1.1:53";
    };
    certs = {
      "${domain}" = {
        dnsProvider = "linode";
        webroot = null;
        credentialFiles."LINODE_TOKEN_FILE" = config.sops.secrets.ACME_KEY.path;
        # group = config.services.nginx.group;
        #dnsPropagationCheck = false; # In case of debugging
      };
    };
  };

  services.nginx = {
    enable = true;
    recommendedGzipSettings = true;
    recommendedOptimisation = true;
    recommendedProxySettings = true;
    recommendedTlsSettings = true;

    virtualHosts = {
      "${domain}" = {
        default = true;
        forceSSL = true;
        enableACME = true;

        root = "${hostDir}/${domain}/current/public";

        locations."/".tryFiles = "$uri $uri/ /index.php?$query_string";

        locations."~ \\.php$".extraConfig = ''
          fastcgi_pass unix:${config.services.phpfpm.pools."${app}".socket};
          fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;
          fastcgi_index index.php;
          include ${pkgs.nginx}/conf/fastcgi_params;
          fastcgi_hide_header X-Powered-By;
        '';

        locations."= /favicon.ico".extraConfig = ''
          access_log off;
          log_not_found off;
        '';
        locations."= /robots.txt".extraConfig = ''
          access_log off;
          log_not_found off;
        '';
        locations."~ /\\.(?!well-known).*".extraConfig = ''
          deny all;
        '';

        extraConfig = ''
          index index.php;
          add_header X-Frame-Options "SAMEORIGIN";
          add_header X-XSS-Protection "1; mode=block";
          add_header X-Content-Type-Options "nosniff";
          charset utf-8;
          error_page 404 /index.php;
        '';
      };

      # Redirect 'www' to 'non-www'
      # "www.${DOMAIN}" = {
      #   forceSSL = true;
      #   enableACME = true;
      #   globalRedirect = DOMAIN;
      # };
    };

    appendHttpConfig = ''
      server {
        listen 127.0.0.1;
        server_name localhost;

        location /nginx_status {
          stub_status on;
          access_log off;
          allow 127.0.0.1;
          deny all;
        }
      }
    '';
  };

  systemd.services.setup-srv-directories = {
    description = "Create directories for rolling release web files";
    wantedBy = ["multi-user.target"];
    script = ''
      mkdir -p ${hostDir}
      chmod 755 ${srv}
      chmod 755 ${hostDir}

      # ${app}
      mkdir -p ${dataDir}/{artifacts,releases,storage}
      mkdir -p ${dataDir}/storage/{app,framework,logs}
      mkdir -p ${dataDir}/storage/app/public
      mkdir -p ${dataDir}/storage/framework/{cache,sessions,views}
      chmod 775 ${dataDir}
      chmod 775 ${dataDir}/artifacts
      chmod 775 ${dataDir}/releases
      chmod -R 775 ${hostDir}/${domain}/storage

      chown -R ${app}:${app} ${hostDir}
    '';
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      User = "root";
    };
  };

  services.phpfpm = {
    phpPackage = pkgs.php83;
    pools."${app}" = {
      user = app;
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
      };
    };
  };

  services.mysql = {
    enable = true;
    package = pkgs.mariadb;
    ensureDatabases = [app];
    ensureUsers = [
      {
        name = app;
        ensurePermissions = {"${app}.*" = "ALL PRIVILEGES";};
      }
      {
        name = config.services.longview.mysqlUser;
        ensurePermissions = {"*.*" = "SELECT, SHOW VIEW, SHOW DATABASES, PROCESS, REPLICATION CLIENT";};
      }
    ];
  };

  systemd.services.mysql-set-passwords = {
    description = "Set MySQL user password";
    wants = ["mysql.service"];
    after = ["sops-nix.service" "mysql.service"];
    wantedBy = ["multi-user.target"];
    script = ''
      ${pkgs.mariadb}/bin/mysql -e "ALTER USER '${app}'@'localhost' IDENTIFIED BY '$(cat ${config.sops.secrets.DB_PW.path})';"
      ${pkgs.mariadb}/bin/mysql -e "ALTER USER '${config.services.longview.mysqlUser}'@'localhost' IDENTIFIED BY '$(cat ${config.sops.secrets.LONGVIEW_DB_PW.path})';"
    '';
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      User = "root";
    };
  };

  services.meilisearch = {
    enable = true;
    environment = "production";
    masterKeyEnvironmentFile = config.sops.templates.MEILISEARCH_KEY_FILE.path;
  };

  services.redis = {
    servers."${app}" = {
      enable = true;
      port = 6379;
      bind = "127.0.0.1";
    };
  };

  # Linode: metric gathering service
  services.longview = {
    enable = true;
    apiKeyFile = config.sops.secrets.LONGVIEW_KEY.path;
    mysqlUser = "longview";
    mysqlPasswordFile = config.sops.secrets.LONGVIEW_DB_PW.path;
  };

  # This option defines the first version of NixOS you have installed on this particular machine,
  # and is used to maintain compatibility with application data (e.g. databases) created on older NixOS versions.
  #
  # Most users should NEVER change this value after the initial install, for any reason,
  # even if you've upgraded your system to a new NixOS release.
  #
  # This value does NOT affect the Nixpkgs version your packages and OS are pulled from,
  # so changing it will NOT upgrade your system.
  #
  # This value being lower than the current NixOS release does NOT mean your system is
  # out of date, out of support, or vulnerable.
  #
  # Do NOT change this value unless you have manually inspected all the changes it would make to your configuration,
  # and migrated your data accordingly.
  #
  # For more information, see `man configuration.nix` or https://nixos.org/manual/nixos/stable/options#opt-system.stateVersion .
  system.stateVersion = "23.11"; # Did you read the comment?
}

{
  pkgs,
  inputs,
  config,
  ...
}: let
  MAINTAINER_EMAIL = "hey@manning390.com";
  USER = "HOSTNAME";
  DOMAIN = "abidanarchive.com";
  DB = "abidan";
in {
  imports = [
    # Include the results of the hardware scan.
    ./hardware-configuration.nix
  ];

  # Use the GRUB 2 boot loader.
  boot.loader.grub.enable = true;

  nix.settings.experimental-features = ["nix-command" "flakes"];

  #networking.enableIPv6 = false;
  networking.usePredictableInterfaceNames = false; # Linode: Linode guides assume eth0
  networking.useDHCP = false; # Linode: Disable DHCP globally, will not need it
  networking.interfaces.eth0.useDHCP = true; # Linode: Required for ssh?
  # Open ports in the firewall.
  networking.firewall.allowedTCPPorts = [80 443];

  # Linode region is Atlanta
  time.timeZone = "America/New_York";

  # Secret management
  sops = {
    defaultSopsFile = ./secrets.yaml;
    defaultSopsFormat = "yaml";
    age.keyFile = "/home/${USER}/.config/sops/age/keys.txt";
    secrets = {
      DB_PASS = {};
      MEILISEARCH_KEY = {
        mode = "0440";
      };
      ACME_KEY = {
        mode = "0440";
        group = "nginx";
      };
      LONGVIEW_KEY = {};
    };
    templates."MEILISEARCH_KEY_FILE".content = "MEILI_MASTER_KEY=${config.sops.placeholder.MEILISEARCH_KEY}";
  };

  users.users."${USER}" = {
    isNormalUser = true;
    home = "/home/${USER}";
    extraGroups = ["wheel" "networkmanager" "nginx" "www-data"];
    openssh.authorizedKeys.keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHJbtlS3h7escz5e1Jgdgc4ZHfH4adAxNq9AwXPWw0+a ${USER}"];
  };
  users.groups.nginx = {};
  users.users.nginx.extraGroups = ["nginx"];

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
  programs.mtr.enable = true;
  # programs.gnupg.agent = {
  #   enable = true;
  #   enableSSHSupport = true;
  # };

  # Services
  # Enable the OpenSSH daemon.
  services.openssh = {
    enable = true;
    settings.PasswordAuthentication = false;
    settings.KbdInteractiveAuthentication = false;
    settings.PermitRootLogin = "no";
  };

  # Linode: metric gathering service
  services.longview = {
    enable = true;
    apiKeyFile = config.sops.secrets.LONGVIEW_KEY.path;
    mysqlUser = "longview";
  };

  services.nginx = {
    enable = true;
    recommendedGzipSettings = true;
    recommendedOptimisation = true;
    recommendedProxySettings = true;
    recommendedTlsSettings = true;

    virtualHosts = {
      "next.${DOMAIN}" = {
        default = true;
        forceSSL = true;
        enableACME = true;

        root = "/home/${USER}/www/${DOMAIN}/current/public";

        locations."/".tryFiles = "$uri $uri/ /index.php?$query_string";

        locations."~ \\.php$".extraConfig = ''
          fastcgi_pass unix:${config.services.phpfpm.pools."${DB}".socket};
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

  # SSL certificate renawl settings
  # /var/lib/acme.challenges must be writable by the ACME user
  # and readable by the nginx user.
  security.acme = {
    acceptTerms = true;
    defaults.email = MAINTAINER_EMAIL;
    defaults.group = "nginx";
    certs = {
      "next.${DOMAIN}" = {
        dnsProvider = "linode";
        webroot = null;
        credentialFiles."LINODE_TOKEN_FILE" = config.sops.secrets.ACME_KEY.path;
        group = config.services.nginx.group;
        dnsPropagationCheck = false; # Disabling until can figure out what's causing this to fail. ipv6?
      };
    };
  };

  services.phpfpm = {
    phpPackage = pkgs.php83;
    pools."${DB}" = {
      user = "nginx";
      group = "nginx";
      settings = {
        "listen.owner" = config.services.nginx.user;
        "pm" = "dynamic";
        "pm.max_children" = 32;
        "pm.start_servers" = 2;
        "pm.min_spare_servers" = 2;
        "pm.max_spare_servers" = 4;
        "pm.max_requests" = 500;
        "security.limit_extensions" = ".php";
        "php_admin_value[disable_functions]" = "exec,passthru,shell_exec,system";
        "php_admin_flag[allow_url_fopen]" = "off";

        "php_flag[display_errors]" = "on";
        "php_admin_value[error_log]" = "/var/log/fpm-php.www.log";
        "php_admin_flag[log_errors]" = "on";
      };
    };
  };

  services.mysql = {
    enable = true;
    package = pkgs.mariadb;
    ensureDatabases = [DB];
    ensureUsers = [
      {
        name = USER;
        ensurePermissions = {"${DB}.*" = "ALL PRIVILEGES";};
      }
      {
        name = "longview";
        ensurePermissions = {"*.*" = "PROCESS, REPLICATION CLIENT";};
      }
    ];
  };

  services.meilisearch = {
    enable = true;
    environment = "production";
    masterKeyEnvironmentFile = config.sops.templates.MEILISEARCH_KEY_FILE.path;
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

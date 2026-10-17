{config, pkgs, ...}: let
  inherit (import ../settings.nix {inherit pkgs;}) app domain hostDir maintainerEmail;
in {
  security.acme = {
    acceptTerms = true;
    defaults = {email = maintainerEmail; dnsResolver = "1.1.1.1:53";};
    certs.${domain} = {
      dnsProvider = "linode";
      webroot = null;
      credentialFiles.LINODE_TOKEN_FILE = config.sops.secrets.ACME_KEY.path;
    };
  };

  services.nginx = {
    enable = true;
    recommendedGzipSettings = true;
    recommendedBrotliSettings = true;
    recommendedOptimisation = true;
    recommendedProxySettings = true;
    recommendedTlsSettings = true;
    clientMaxBodySize = "102M";

    virtualHosts = {
      ${domain} = {
        default = true;
        forceSSL = true;
        enableACME = true;
        root = "${hostDir}/${domain}/current/public";
        locations = {
          "/".tryFiles = "$uri $uri/ /index.php?$query_string";
          "~ \\.php$".extraConfig = ''
            fastcgi_pass unix:${config.services.phpfpm.pools.${app}.socket};
            fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;
            fastcgi_index index.php;
            include ${pkgs.nginx}/conf/fastcgi_params;
            fastcgi_hide_header X-Powered-By;
          '';
          "= /favicon.ico".extraConfig = ''
            access_log off;
            log_not_found off;
          '';
          "= /robots.txt".extraConfig = ''
            access_log off;
            log_not_found off;
          '';
          "~ /\\.(?!well-known).*".extraConfig = ''
            deny all;
          '';
        };
        extraConfig = ''
          index index.php;
          add_header X-Frame-Options "SAMEORIGIN";
          add_header X-XSS-Protection "1; mode=block";
          add_header X-Content-Type-Options "nosniff";
          charset utf-8;
          error_page 404 /index.php;
        '';
      };
      "www.${domain}" = {
        forceSSL = true;
        enableACME = true;
        globalRedirect = domain;
      };
      # The current live wiki proxy, will change to the new wiki after migration/testing.
      "wiki.${domain}" = {
        forceSSL = true;
        enableACME = true;
        locations."/" = {
          recommendedProxySettings = false;
          proxyPass = "https://208.115.98.20";
          extraConfig = ''
            proxy_ssl_verify off;
            proxy_set_header Host wiki.abidanarchive.com;
          '';
        };
      };
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
}

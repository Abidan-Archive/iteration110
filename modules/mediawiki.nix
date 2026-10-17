{config, pkgs, lib, ...}: let
  inherit (import ../settings.nix {inherit pkgs;}) domain wikiDomain;
  clientSecretPath = config.sops.secrets.MEDIAWIKI_OAUTH_CLIENT_SECRET.path;
in {
  services.phpfpm.pools.mediawiki.phpOptions = ''
    upload_max_filesize = 500M
    post_max_size = 512M
  '';
  services.mediawiki = {
    enable = true;
    name = "Abidan Archive Wiki";
    url = "https://${wikiDomain}";
    webserver = "nginx";
    nginx.hostName = wikiDomain;
    passwordFile = config.sops.secrets.MEDIAWIKI_INIT_ADMIN_PW.path;
    database = {type = "mysql"; createLocally = true;};
    poolConfig = {
      "pm" = "dynamic";
      "pm.max_children" = 10;
      "pm.start_servers" = 2;
      "pm.min_spare_servers" = 1;
      "pm.max_spare_servers" = 3;
      "pm.max_requests" = 500;
    };
    extensions = {
      AbidanUsernameSync = ../mediawiki/AbidanUsernameSync;
      PluggableAuth = pkgs.fetchzip {
        url = "https://extdist.wmflabs.org/dist/extensions/PluggableAuth-REL1_45-2bf2ad2.tar.gz";
        hash = "sha256-79myI1DX6B2YLmXSphdtVwb6pxe8lh5ZKRLogVxMHV4=";
      };
      OpenIDConnect = pkgs.fetchzip {
        url = "https://extdist.wmflabs.org/dist/extensions/OpenIDConnect-REL1_45-0f501b2.tar.gz";
        hash = "sha256-mLJgYw/Iq1yrt/YR90dzWDL0umyNapFBDBoovGllkJA=";
      };
      Spoilers = pkgs.fetchzip {
        url = "https://github.com/Telshin/Spoilers/archive/e092f1ce2117c85c9d97cc9315e6b9445001fa1d.tar.gz";
        hash = "sha256-2xLJnOEl4RrATMxN533v3dcFTylXQbLu9naRlNQ/twI=";
      };
      Scribunto = null;
      TemplateStyles = null;
      ParserFunctions = null;
      Cite = null;
    };
    extraConfig = /* php */''
      $wgVectorNightMode['beta'] = true;
      $wgVectorNightMode['logged_out'] = true;
      $wgVectorNightMode['logged_in'] = true;
      $wgDefaultUserOptions['vector-theme'] = 'os';

      $wgScribuntoDefaultEngine = 'luastandalone';
      // Scribunto expects bytes, not PHP ini shorthand such as "50M".
      $wgScribuntoEngineConf['luastandalone']['memoryLimit'] = 50 * 1024 * 1024;

      $wgPluggableAuth_Config = [
          'Abidan Archive' => [
              'plugin' => 'AbidanOpenIDConnect',
              'data' => [
                  'providerURL' => 'https://${domain}',
                  'clientID' => 'mediawiki',
                  'clientsecret' => trim(file_get_contents('${clientSecretPath}')),
                  'codeChallengeMethod' => 'S256'
              ],
              'groupsyncs' => [
                  [
                      'type' => 'mapped',
                      'map' => [
                          'sysop' => [ 'wiki_roles' => 'wiki_admin' ],
                          'moderator' => [ 'wiki_roles' => 'wiki_moderator' ]
                      ]
                  ]
              ]
          ]
      ];
      $wgPluggableAuth_EnableAutoLogin = false;
      $wgPluggableAuth_EnableLocalLogin = false;
      $wgPluggableAuth_EnableLocalProperties = false;
      $wgGroupPermissions['*']['createaccount'] = false;
      $wgGroupPermissions['*']['edit'] = false;
      $wgGroupPermissions['*']['autocreateaccount'] = true;

      // Archive ACL owns privileged membership, synchronized on wiki login.
      foreach ( [ 'block', 'blockemail', 'delete', 'undelete', 'deletedhistory',
          'deletedtext', 'protect', 'rollback', 'patrol', 'autopatrol' ] as $right ) {
          $wgGroupPermissions['moderator'][$right] = true;
      }
      $wgGroupPermissions['bureaucrat']['userrights'] = false;

      $wgDebugLogGroups['AbidanUsernameSync'] = '/var/log/mediawiki/username-sync.log';
    '';
  };
  services.nginx.virtualHosts.${wikiDomain} = {
    forceSSL = true;
    enableACME = true;
    extraConfig = ''
      client_max_body_size 512m;
    '';
    locations."= /".extraConfig = lib.mkForce ''
      return 302 /wiki/Welcome;
    '';
  };
  systemd.tmpfiles.rules = ["d /var/log/mediawiki 0750 mediawiki nginx - -"];
  services.logrotate.settings.mediawiki = {
    files = ["/var/log/mediawiki/username-sync.log"];
    frequency = "daily";
    rotate = 14;
    compress = true;
    missingok = true;
    notifempty = true;
    create = "0640 mediawiki nginx";
  };
}

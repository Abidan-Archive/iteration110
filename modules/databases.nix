{config, pkgs, ...}: let
  inherit (import ../settings.nix {inherit pkgs;}) app;
in {
  services.mysql = {
    enable = true;
    package = pkgs.mariadb;
    ensureDatabases = [app];
    ensureUsers = [
      {name = app; ensurePermissions = {"${app}.*" = "ALL PRIVILEGES";};}
      {
        name = config.services.longview.mysqlUser;
        ensurePermissions = {"*.*" = "SELECT, SHOW VIEW, SHOW DATABASES, PROCESS, REPLICATION CLIENT";};
      }
    ];
  };
  systemd.services.mysql-set-passwords = {
    description = "Set MySQL user password";
    wants = ["mysql.service"];
    after = ["sops-install-secrets.service" "mysql.service"];
    wantedBy = ["multi-user.target"];
    script = ''
      ${pkgs.python3}/bin/python ${../scripts/set-mysql-passwords.py} \
        ${pkgs.mariadb}/bin/mysql \
        '${app}' ${config.sops.secrets.DB_PW.path} \
        '${config.services.longview.mysqlUser}' ${config.sops.secrets.LONGVIEW_DB_PW.path}
    '';
    serviceConfig = {Type = "oneshot"; RemainAfterExit = true; User = "root";};
  };
  services.meilisearch = {
    enable = true;
    settings.env = "production";
    masterKeyFile = config.sops.secrets.MEILISEARCH_KEY.path;
  };
  services.redis.servers.${app} = {
    enable = true;
    port = 6379;
    bind = "127.0.0.1";
  };
}

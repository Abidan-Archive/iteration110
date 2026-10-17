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
    after = ["sops-nix.service" "mysql.service"];
    wantedBy = ["multi-user.target"];
    script = ''
      ${pkgs.mariadb}/bin/mysql -e "ALTER USER '${app}'@'localhost' IDENTIFIED BY '$(cat ${config.sops.secrets.DB_PW.path})';"
      ${pkgs.mariadb}/bin/mysql -e "ALTER USER '${config.services.longview.mysqlUser}'@'localhost' IDENTIFIED BY '$(cat ${config.sops.secrets.LONGVIEW_DB_PW.path})';"
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

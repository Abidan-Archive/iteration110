{config, ...}: {
  services.longview = {
    enable = true;
    apiKeyFile = config.sops.secrets.LONGVIEW_KEY.path;
    mysqlUser = "longview";
    mysqlPasswordFile = config.sops.secrets.LONGVIEW_DB_PW.path;
  };
}

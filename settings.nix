{pkgs}: let
  app = "abidan";
  domain = "abidanarchive.com";
  srv = "/srv";
  hostDir = "${srv}/http";
in {
  inherit app domain srv hostDir;
  dataDir = "${hostDir}/${domain}";
  wikiDomain = "next.${domain}";
  deployer = "telariel";
  maintainerEmail = "hey@manning390.com";

  phpPackage = pkgs.php83.buildEnv {
    extensions = {enabled, all}:
      enabled ++ (with all; [ctype curl dom fileinfo mbstring openssl pdo session tokenizer redis]);
  };
}

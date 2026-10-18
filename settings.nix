{pkgs}: let
  app = "abidan";
  domain = "abidanarchive.com";
  srv = "/srv";
  hostDir = "${srv}/http";
in {
  inherit app domain srv hostDir;
  dataDir = "${hostDir}/${domain}";
  wikiDomain = "next.${domain}";
  administrator = "telariel";
  deployer = "abidan-deploy";
  deploymentAuthorizedKeys = [
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAwZcAoHztHqhRj8uR06+SXsDphc0Kc/EGPEP9on728/ abidan-github-actions"
  ];
  maintainerEmail = "hey@manning390.com";

  phpPackage = pkgs.php83.buildEnv {
    extensions = {
      enabled,
      all,
    }:
      enabled ++ (with all; [ctype curl dom fileinfo mbstring openssl pdo session tokenizer redis]);
  };
}

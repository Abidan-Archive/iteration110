{inputs, ...}: {
  imports = [
    ./hardware-configuration.nix
    ./modules/system.nix
    ./modules/users.nix
    ./modules/secrets.nix
    ./modules/nginx.nix
    ./modules/archive.nix
    ./modules/databases.nix
    ./modules/monitoring.nix
    ./modules/mediawiki.nix
  ];

  services.abidan.environment = {
    enable = true;
    sopsFile = "${inputs.abidan-environment}/secrets/production.env";
  };

  # Keep the installation's original compatibility defaults across upgrades.
  system.stateVersion = "23.11";
}

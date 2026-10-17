{pkgs, ...}: let
  inherit (import ../settings.nix {inherit pkgs;}) app deployer;
in {
  users.users = {
    ${deployer} = {
      isNormalUser = true;
      extraGroups = ["wheel" "networkmanager" "nginx" app];
      openssh.authorizedKeys.keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHJbtlS3h7escz5e1Jgdgc4ZHfH4adAxNq9AwXPWw0+a ${deployer}"];
    };
    ${app} = {
      group = app;
      isSystemUser = true;
    };
    nginx.extraGroups = ["acme" app];
  };
  users.groups = {
    ${app} = {};
    nginx = {};
  };
  # Deployment may request the fixed, host-owned cache refresh. No sudo
  # password, arbitrary Artisan command, or unrestricted systemctl is needed.
  security.sudo.extraRules = [{
    users = [deployer];
    commands = [{
      command = "/run/current-system/sw/bin/systemctl restart abidan-config-refresh.service";
      options = ["NOPASSWD"];
    }];
  }];
}

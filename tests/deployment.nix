{inputs}: let
  host = inputs.nixpkgs.lib.nixosSystem {
    system = "x86_64-linux";
    specialArgs = {inherit inputs;};
    modules = [../configuration.nix inputs.sops-nix.nixosModules.sops];
  };
  c = host.config;
  settings = import ../settings.nix {pkgs = host.pkgs;};
  deployRules = builtins.filter (rule: builtins.elem settings.deployer rule.users) c.security.sudo.extraRules;
in
  assert c.users.users.${settings.deployer}.extraGroups == [settings.app];
  assert !(builtins.elem settings.deployer c.nix.settings.trusted-users);
  assert c.systemd.services.setup-srv-directories.serviceConfig.User == settings.app;
  assert c.systemd.services.setup-deployment-directories.serviceConfig.User == settings.deployer;
  assert c.systemd.services.abidan-config-refresh.serviceConfig.User == settings.app;
  assert builtins.elem "d ${settings.dataDir} 1775 root ${settings.app} - -" c.systemd.tmpfiles.rules;
  assert builtins.length deployRules == 1;
  assert (builtins.head deployRules).commands == [{
    command = "/run/current-system/sw/bin/systemctl restart abidan-config-refresh.service";
    options = ["NOPASSWD"];
  }];
  assert toString c.sops.age.keyFile == "/home/${settings.administrator}/.config/sops/age/keys.txt";
  {
    passed = true;
    deploymentUser = settings.deployer;
    administrator = settings.administrator;
    # Force evaluation of scripts, including the external SQL helper path.
    databaseScript = c.systemd.services.mysql-set-passwords.script;
  }

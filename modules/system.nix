{pkgs, ...}: let
  inherit (import ../settings.nix {inherit pkgs;}) administrator;
in {
  boot.loader.grub.enable = true;
  nix.settings.experimental-features = ["nix-command" "flakes"];
  nix.settings.trusted-users = ["root" administrator "@wheel"];

  # IPv6 DNS lookups fail on this Linode VM, including lego's ACME queries.
  networking = {
    enableIPv6 = false;
    usePredictableInterfaceNames = false;
    useDHCP = false;
    interfaces.eth0.useDHCP = true;
    firewall.allowedTCPPorts = [80 443];
    nameservers = ["8.8.8.8" "1.1.1.1"];
  };
  time.timeZone = "America/New_York";

  environment.systemPackages = with pkgs; [
    vim
    wget
    inetutils
    mtr
    sysstat
    git
    nh
    htop
  ];
  programs.nh = {
    enable = true;
    clean.enable = true;
    clean.extraArgs = "--keep-since 5d --keep 3";
    flake = "/etc/nixos";
  };
  programs.mtr.enable = true;
  services.openssh = {
    enable = true;
    settings = {
      PasswordAuthentication = false;
      KbdInteractiveAuthentication = false;
      PermitRootLogin = "no";
    };
  };
}

{
  pkgs,
  lib,
  config,
  inputs,
  ...
}: {
  # https://devenv.sh/basics/
  # env.GREET = "devenv";

  # https://devenv.sh/packages/
  packages = with pkgs; [
    git
    sops
    alejandra
  ];

  scripts.deploy.exec = ''
    NIX_SSHOPTS="-o RequestTTY=force" nixos-rebuild -j auto --flake .#nixos --target-host abidan --use-remote-sudo switch
  '';

  # See full reference at https://devenv.sh/reference/options/
}

{
  description = "Abidan Archive Server Site";

  nixConfig = {};

  inputs = {
    # Nixpkgs
    nixpkgs.url = "github:nixos/nixpkgs/nixos-26.05";
    nixpkgs-unstable.url = "github:nixos/nixpkgs/nixos-unstable";

    # Home manager
    # home-manager.url = "github:nix-community/home-manager/release-24.05";
    # home-manager.inputs.nixpkgs.follows = "nixpkgs";

    # Secrets
    sops-nix.url = "github:Mic92/sops-nix";
    sops-nix.inputs.nixpkgs.follows = "nixpkgs";

    abidan-environment = {
      url = "github:Abidan-Archive/archive/prod";
      flake = false;
    };
    nixpkgs-php.url = "github:nixos/nixpkgs/8c259fc0dd1f3ccc1aaf4f9156ab16b7328b5a4f";
  };

  outputs = {
    self,
    nixpkgs,
    ...
  } @ inputs: let
    inherit (self) outputs;
  in {
    formatter = nixpkgs.lib.genAttrs ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"] (
      system: nixpkgs.legacyPackages.${system}.alejandra
    );

    nixosConfigurations.abidan = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      specialArgs = {inherit inputs outputs;};
      modules = [
        inputs.sops-nix.nixosModules.sops
        {
          nixpkgs.overlays = [
            (final: prev: let
              system = prev.stdenv.hostPlatform.system;
              patchedPkgs = inputs.nixpkgs-php.legacyPackages.${system};
            in {
              php83 = patchedPkgs.php83;
              php83Packages = patchedPkgs.php83Packages;
            })
          ];
        }
        ./configuration.nix
      ];
      # home-manager.useGlobalPkgs = true;
      # home-manager.extraSpecialArgs = {inherit inputs outputs vars;};
      # home-manager.users.HOSTUSER = import ./home.nix;
    };
  };
}

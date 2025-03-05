{
    description = "Abidan Archive Server Site";

    nixConfig = {};

    inputs = {
        # Nixpkgs
        nixpkgs.url = "github:nixos/nixpkgs/nixos-24.11";
        nixpkgs-unstable.url = "github:nixos/nixpkgs/nixos-unstable";

        # Home manager
        # home-manager.url = "github:nix-community/home-manager/release-24.05";
        # home-manager.inputs.nixpkgs.follows = "nixpkgs";

        # Secrets
        sops-nix.url = "github:Mic92/sops-nix";
        sops-nix.inputs.nixpkgs.follows = "nixpkgs";
    };

    outputs = {
        self,
        nixpkgs,
        ...
    } @ inputs:
    let
        inherit (self) outputs;
    in {
        nixosConfigurations.nixos = nixpkgs.lib.nixosSystem {
            system = "x86_64-linux";
            specialArgs = {inherit inputs outputs;};
            modules = [
                inputs.sops-nix.nixosModules.sops
                ./configuration.nix
            ];
            # home-manager.useGlobalPkgs = true;
            # home-manager.extraSpecialArgs = {inherit inputs outputs vars;};
            # home-manager.users.HOSTUSER = import ./home.nix;
        };
    };
}

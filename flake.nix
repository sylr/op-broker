{
  description = "Resolve 1Password op:// references over Tailscale";

  inputs = {
    nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0.2605";
  };

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      forEachSupportedSystem = f:
        nixpkgs.lib.genAttrs supportedSystems (system:
          f {
            pkgs = import nixpkgs { inherit system; };
            inherit system;
          });
    in
    {
      # Every tool used to build, test and release comes from these shells,
      # locally (via direnv) and in CI (`nix develop .#ci-<job>`). Names match
      # the workflow jobs.
      devShells = forEachSupportedSystem ({ pkgs, system }:
        let
          # Must match go.mod's `go` directive: GOTOOLCHAIN=local makes go
          # fail instead of downloading a different toolchain, so bumping
          # go.mod past this version requires bumping nixpkgs too.
          go = pkgs.go_1_27;

          # mkShell (not mkShellNoCC): `go test -race` needs cgo and a C
          # compiler.
          mkGoShell = packages: pkgs.mkShell {
            inherit packages;
            env.GOTOOLCHAIN = "local";
          };
        in
        rec {
          ci-test = mkGoShell [ go pkgs.git ];

          # goreleaser builds with go, generates SBOMs with syft and reads
          # tags with git. Used by both the CI snapshot and the release.
          ci-goreleaser = mkGoShell [ go pkgs.git pkgs.goreleaser pkgs.syft ];

          default = mkGoShell (ci-goreleaser.nativeBuildInputs ++ [ pkgs.gnumake ]);
        });
    };
}

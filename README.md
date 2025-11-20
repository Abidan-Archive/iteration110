# Iteration110 Server Config
The abidan archive runs on a nixos linux server. This repo contains the configurations for that server.

## Deploy
Easiest way to do this is to download the repo on an existing nixos system. Then run this command substituting the correct ssh connection.
`nixos-rebuilt -j auto switch --flake .#nixos --target-host USER@HOSTNAME --verbose --use-remote-sudo`

You will need to ensure the user via the ssh connection has wheel permissions in order to activate the configuration.

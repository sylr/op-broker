#!/bin/sh
# Generates opb's shell completion scripts into completions/ for the release
# archives and packages.
set -e
rm -rf completions
mkdir completions
go run ./cmd/opb completion bash >completions/opb.bash
# zsh autoloads completion functions by file name.
go run ./cmd/opb completion zsh >completions/_opb
go run ./cmd/opb completion fish >completions/opb.fish

# op-broker

A broker for 1Password: resolve 1Password secret references
(`op://vault/item/field`) from any machine on your tailnet. The 1Password CLI
runs only on your Mac.

> op-broker is an independent project. It is not affiliated with, endorsed by
> or sponsored by 1Password. 1Password is a trademark of AgileBits Inc.

- **`opbd`** runs on the Mac. It joins the tailnet as its own node (embedded
  [tsnet](https://tailscale.com/kb/1244/tsnet)), identifies each caller with
  Tailscale WhoIs, checks the caller against an allowlist, and resolves
  references with the local `op` CLI through 1Password desktop-app
  integration.
- **`opb`** runs anywhere on the tailnet and supports part of the `op`
  interface: `read`, `inject`, `run` and `item get`.

```
remote host                              Mac
┌──────────┐  HTTP over tailnet   ┌────────────────────────────┐
│   opb    │ ───────────────────▶ │ opbd (tsnet node op-broker)│
└──────────┘  POST /v1/...        │  WhoIs → policy → queue →  │──▶ 1Password.app
                                  │  exec op (clean env)       │
                                  └────────────────────────────┘
```

## How approval works

`opbd` uses your own signed-in 1Password app. It never uses service accounts,
Connect or session tokens: they are stripped from the `op` environment. These
results come from testing `op` 2.41 started by a LaunchAgent with no TTY:

- The **first request after `opbd` starts** shows a 1Password approval prompt
  (Touch ID) on the Mac.
- Approval lasts for the life of the `opbd` process. Later requests do not
  prompt.
- After **10 minutes without requests**, or once 1Password is **locked**, the
  next request prompts again.
- If you dismiss the prompt, or nobody approves it within `op.timeout`
  (default 60s), the client fails with exit status 3 and gets no secret.

So remote callers can only read secrets while you are at the Mac or have
approved recently. That is a deliberate consequence of using desktop
integration.

## Install

On macOS, with Homebrew (installs `opb` and `opbd`):

```sh
brew install --cask sylr/tap/op-broker
```

On Linux, install the `opb` `.deb` or `.rpm` from the
[releases](https://github.com/sylr/op-broker/releases), or use the
archives (which also exist for Windows and FreeBSD). From source:

```sh
make install          # go install opb and opbd into GOBIN (or GOPATH/bin)
```

With a Homebrew install, point the LaunchAgent at Homebrew's `opbd` (step 3
below) with `make install-agent INSTALL_DIR=$(brew --prefix)/bin`, run from a
checkout.

### Server (Mac)

1. Write the configuration from [`config.example.yaml`](config.example.yaml):

   ```sh
   mkdir -m 700 -p ~/Library/Application\ Support/op-broker
   cp config.example.yaml ~/Library/Application\ Support/op-broker/config.yaml
   chmod 600 ~/Library/Application\ Support/op-broker/config.yaml
   op account list    # put the account UUID in op.account
   ```

2. Join the tailnet once, interactively, **as yourself**. The broker must be
   an untagged node owned by your user, because that is how clients
   recognize it:

   ```sh
   opbd    # prints a login.tailscale.com URL: open it and sign in
   ```

   An untagged auth key (`TS_AUTHKEY=tskey-auth-... opbd`) works too. Don't
   use a tagged key. The node state is saved in `state_dir`, so later starts
   need no login. Stop it with Ctrl-C.

   In the admin console, **disable key expiry** for the `op-broker` node.
   Otherwise the node expires after the tailnet's key lifetime (180 days by
   default), and `opbd` needs a new interactive login.

3. Run it as a LaunchAgent. It must be an agent in your GUI session, not a
   daemon:

   ```sh
   make install install-agent    # from source: writes ~/Library/LaunchAgents/com.sylr.op-broker.plist and loads it
   ```

4. Restrict who can reach the broker in your tailnet policy. The broker is an
   ordinary device of yours, so name it with a host alias set to its
   Tailscale IP (`tailscale ip op-broker`). Grants are additive: if a broader
   rule (for example the default allow-all) already lets everyone reach your
   devices, narrow it.

   ```jsonc
   "hosts": { "op-broker": "100.x.y.z" },
   "grants": [
     { "src": ["sylvain@formance.com", "tag:ci"], "dst": ["op-broker"], "ip": ["tcp:80"] }
   ]
   ```

### Client

```sh
export OPB_SERVER=http://op-broker.<tailnet>.ts.net   # default: http://op-broker
```

Use the full MagicDNS name. Before sending anything, the client
authenticates the broker:

- It only connects to Tailscale addresses (`100.64.0.0/10`,
  `fd7a:115c:a1e0::/48`).
- It asks the **local Tailscale daemon** who owns the address it connected
  to, and checks it against the expected broker identity. If the local daemon
  cannot be reached, the client refuses to connect.

The expected identity comes from `OPB_BROKER` (or `--broker`):

| Value | The broker must be |
|---|---|
| *(unset)* | an untagged node owned by the same user as this machine |
| `user:<login>` | an untagged node owned by `<login>` |
| `node:<stable-id>` | that exact node |
| `tag:<name>` | a node carrying that ACL tag |

Your own machines need no setting. **Tagged machines (CI, servers) must set
it**, e.g. `OPB_BROKER=user:sylvain@formance.com`. A tagged machine has no
owner to derive the identity from, so `opb` refuses to run there without it.

Address ranges alone would not be enough, because other networks also use
the CGNAT range. `--allow-non-tailnet` (or `OPB_ALLOW_NON_TAILNET=1`) turns
both checks off. It is insecure and meant for testing only.

#### Configuration file

Instead of environment variables, `opb` can read contexts (brokers) and env
bundles from `~/.config/op-broker/opb.yaml` (`$XDG_CONFIG_HOME/op-broker/opb.yaml`
if set, or `$OPB_CONFIG`, or `--config`). See
[`opb.example.yaml`](opb.example.yaml). The file holds no secrets, but it
decides which broker gets your requests. On Unix, `opb` therefore refuses it
if it, or any directory that could redirect it, is writable by group or others
or owned by another user. "Any directory" means the ancestors of the path and
of every symlink target on the way to the file. Root-owned files and sticky
directories are allowed, so files from the Nix store work. On Windows these
checks are not made: keep the file in your profile directory, whose ACLs
protect it.

```yaml
current_context: home
contexts:
  home:
    server: http://op-broker.<tailnet>.ts.net
  work:
    server: http://op-broker.<other-tailnet>.ts.net
    broker: tag:op-broker
bundles:
  aws-prod:
    context: work          # optional: always use this context
    env:
    - name: AWS_ACCESS_KEY_ID
      ref: op://<vault>/aws-prod/access key id
    - name: AWS_SECRET_ACCESS_KEY
      ref: op://<vault>/aws-prod/secret access key
```

- **Contexts.** The active context is `--context`, then `$OPB_CONTEXT`, then
  `current_context`. `opb context use <name>` rewrites only the
  `current_context` line, so comments are kept; it refuses symlinked files,
  which are usually managed by another tool.
- **Overrides.** Every context needs a `server`. Flags override environment
  variables, which override the context (`--server`/`OPB_SERVER`, `--broker`/`OPB_BROKER`,
  `--allow-non-tailnet`/`OPB_ALLOW_NON_TAILNET`). A context's `broker` and
  `allow_non_tailnet` describe its own `server`, so they are dropped once the
  server comes from a flag or the environment: an insecure test context can
  never turn off verification of another server. `OPB_ALLOW_NON_TAILNET=0`
  turns off a context's `allow_non_tailnet`.
- **Bundles.** A bundle maps environment variable names to references. Later
  bundles override earlier ones. A bundle with a `context` always resolves on
  that broker: `OPB_CONTEXT`, `OPB_SERVER`, `OPB_BROKER` and
  `OPB_ALLOW_NON_TAILNET` are ignored, and `--server`, `--broker`,
  `--allow-non-tailnet` or a different `--context` are errors, as is
  combining bundles pinned to different contexts.

## Usage

```sh
opb read op://Dev/postgres/password
opb read -n "op://Dev/github/one-time password?attribute=otp"

opb inject -i config.tpl -o config.yaml       # output written with mode 0600

opb run --env-file .env -- ./deploy.sh        # DB_PASSWORD=op://Dev/postgres/password in .env
opb run --bundle aws-prod -- terraform plan   # bundle from the configuration file
eval "$(opb env aws-prod)"                    # export a bundle into the current shell

opb context list                              # * marks the active context
opb context show [name]                       # effective server and broker identity
opb context use work

opb item get postgres --vault Dev             # whole item as JSON (needs an items grant)
```

Exit status: `0` success, `1` error, `2` access denied, `3` 1Password locked,
or approval not given in time on the Mac.

## Access rules

Everything not granted is denied. See [`config.example.yaml`](config.example.yaml).

- `user:<login>` matches **untagged** devices of that Tailscale user.
- `tag:<name>` matches tagged devices. A tagged device **never** matches a
  `user:` principal, even the user who created it, so a CI box you set up does
  not get your personal access.
- `node:<stable-id>` matches one device by its stable ID, which, unlike
  device names, can't be changed or reused.
- The principals of a rule are ORed together.
- `read` patterns grant field reads. `items` patterns grant whole-item JSON,
  and are never implied by `read`.
- Matching is case-insensitive, like `op`. `*` matches one segment and a final
  `**` matches the rest.
- A field grant covers every attribute of the field. A grant on a one-time
  password field also exposes its TOTP seed.
- Rules may name vaults and items by name or ID. Renaming in 1Password changes
  what a name-based rule covers, so prefer IDs for sensitive grants. Rules
  match case-insensitively, so avoid names that differ only in case.
- Rules compare the names in a reference literally, and some vaults have
  more than one. In a business account, `op` accepts both `Employee` and
  `Private` for your personal vault, so a rule on `op://Employee/**` does not
  cover a request for `op://Private/...`. This can only deny, never allow,
  too much. Use the vault ID instead (`op vault list`), which is unambiguous:
  `op://<vault-id>/**`.
- The configuration file must be owned by you, mode `0600`, not a symlink, and
  in a directory that only you can write to. Otherwise `opbd` refuses to start
  or reload.

Reload rules without restarting:

```sh
launchctl kill HUP gui/$(id -u)/com.sylr.op-broker
```

A reload applies to new requests. Requests already being handled finish
under the rules they started with. If the new file is invalid, for example
because it has a second YAML document, `opbd` logs an error and keeps the
previous rules.

## Trust boundary

- Tailscale WhoIs identifies a **device**, not a user or a process on it. Any
  process on an allowed device can read what that device is allowed to read.
- Traffic relayed by a subnet router, `tailscale serve` or a reverse proxy is
  identified as the relaying node, whichever principal you use for it. Every
  caller that can reach the relay gets the relay's grants, so **don't grant
  secrets to nodes that relay traffic for others.**
- Clients only talk to an untagged node owned by the expected user (or the
  pinned node or tag). Only that user can register such nodes. Any of the
  user's other untagged devices could therefore answer as the broker, so use
  `OPB_BROKER=node:<stable-id>` to pin the exact node if those devices are
  less trusted than the Mac.
- Traffic is plain HTTP inside WireGuard. The client never uses HTTP proxies
  and never follows redirects. The server rejects requests that carry an
  `Origin` header, are not `application/json`, or have a `Host` other than its
  own, which blocks browsers and DNS rebinding.
- Secret references are parsed strictly (no `%`-escapes, wildcards, `..`, or
  unknown query keys). The canonical form is both what is authorized and what
  is passed to `op`.
- Errors returned to clients are generic codes. The output of `op` is never
  returned or logged.

## Audit log

Each request produces one JSON line in `log_file`. It records caller login,
node ID and name, tags, operation, canonical refs, decision, error code and
duration. It never records values. To rotate, move the file and send `SIGHUP`
to reopen it:

```sh
mv ~/Library/Logs/op-broker.log ~/Library/Logs/op-broker.log.1
launchctl kill HUP gui/$(id -u)/com.sylr.op-broker
```

## Limitations

- **`opb run` does not mask output.** Unlike `op run`, secrets printed by
  the command appear in clear.
- **`opb env` puts secrets in your shell.** Every command the shell runs
  afterwards inherits them; prefer `opb run --bundle` when one command needs
  them.
- `inject` supports `{{ op://... }}` with `$VAR` / `${VAR}` inside the
  reference. Bare references, escapes and defaults are rejected rather than
  passed through.
- `run` only resolves variables whose whole value is a reference, as `op run`
  does. Precedence also matches `op run`: env files override the shell
  environment, and later files override earlier ones; `--bundle` variables
  override both. The command is looked up in the resulting `PATH`, and
  relative entries are skipped. The env-file format is a subset of dotenv
  (see `ParseDotenv`) with no interpolation.
- Values must be UTF-8 text. Binary file attachments are rejected.
- All `op` calls are serialized, and a batch is all-or-nothing: if one
  reference is denied, missing or fails, nothing is returned. One command can
  use at most 100 distinct references with at most 8 MiB of values in total.
  The server handles at most 64 API requests at once.
- `request_timeout` is capped at 140s, so the server always answers before the
  client gives up (150s).
- `opb run` uses `exec(2)` and supports Unix only.

## Development

The flake provides every tool used to build, test and release (go,
goreleaser, syft, git, make), and CI uses the same shells. Run `nix develop`
or let direnv load `.envrc`, then use `make build`, `make test` or
`goreleaser release --snapshot --clean`.

The shells set `GOTOOLCHAIN=local`, so go never downloads a toolchain. Raising
the `go` directive in `go.mod` above the flake's go needs a nixpkgs bump
(`nix flake update`).

## License

[MIT](LICENSE)

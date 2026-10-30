# 1password-broker

Resolve 1Password secret references (`op://vault/item/field`) from any machine
on your tailnet. The 1Password CLI runs only on your Mac.

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

```sh
make install          # go install opb and opbd into $(go env GOPATH)/bin
```

### Server (Mac)

1. Write the configuration from [`config.example.yaml`](config.example.yaml):

   ```sh
   mkdir -m 700 -p ~/Library/Application\ Support/op-broker
   cp config.example.yaml ~/Library/Application\ Support/op-broker/config.yaml
   chmod 600 ~/Library/Application\ Support/op-broker/config.yaml
   op account list    # put the account UUID in op.account
   ```

2. Join the tailnet once, interactively. Create a **tagged** auth key
   (`tag:op-broker`) in the Tailscale admin console, then run:

   ```sh
   TS_AUTHKEY=tskey-auth-... opbd
   ```

   The node state is saved in `state_dir`, so later starts need no key. Stop
   it with Ctrl-C.

3. Run it as a LaunchAgent. It must be an agent in your GUI session, not a
   daemon:

   ```sh
   make install-agent    # writes ~/Library/LaunchAgents/com.sylr.op-broker.plist and loads it
   ```

4. Restrict who can reach the broker in your tailnet policy. Grants are
   additive: if a broader rule (for example the default allow-all) already
   lets everyone reach `tag:op-broker`, remove or narrow it.

   ```jsonc
   "tagOwners": { "tag:op-broker": ["autogroup:admin"] },
   "grants": [
     { "src": ["sylvain@formance.com", "tag:ci"], "dst": ["tag:op-broker"], "ip": ["tcp:80"] }
   ]
   ```

### Client

```sh
export OPB_SERVER=http://op-broker.<tailnet>.ts.net   # default: http://op-broker
```

Use the full MagicDNS name. The client only connects to Tailscale addresses
(`100.64.0.0/10`, `fd7a:115c:a1e0::/48`), so a LAN host answering to
`op-broker` cannot impersonate the broker. `--allow-non-tailnet` (or
`OPB_ALLOW_NON_TAILNET=1`) lifts this restriction for testing.

## Usage

```sh
opb read op://Dev/postgres/password
opb read -n "op://Dev/github/one-time password?attribute=otp"

opb inject -i config.tpl -o config.yaml       # output written with mode 0600

opb run --env-file .env -- ./deploy.sh        # DB_PASSWORD=op://Dev/postgres/password in .env

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
- The configuration file must be owned by you, mode `0600`, not a symlink, and
  in a directory that only you can write to. Otherwise `opbd` refuses to start
  or reload.

Reload rules without restarting:

```sh
launchctl kill HUP gui/$(id -u)/com.sylr.op-broker
```

## Trust boundary

- Tailscale WhoIs identifies a **device**, not a user or a process on it. Any
  process on an allowed device can read what that device is allowed to read.
- Traffic relayed by a subnet router, `tailscale serve` or a reverse proxy is
  identified as the relaying node. Every client behind that node gets its
  grants, so don't grant secrets to such nodes, or grant them by `node:`
  only.
- Inside the tailnet, any member could register a node with the broker's name
  while it is offline. Restrict who can create `tag:op-broker` nodes and set
  `OPB_SERVER` to the exact name the broker logs at startup.
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
- `inject` supports `{{ op://... }}` with `$VAR` / `${VAR}` inside the
  reference. Bare references, escapes and defaults are rejected rather than
  passed through.
- `run` only resolves variables whose whole value is a reference, as `op run`
  does. The env-file format is a subset of dotenv (see `ParseDotenv`) with no
  interpolation.
- Values must be UTF-8 text. Binary file attachments are rejected.
- All `op` calls are serialized, and a batch is all-or-nothing: if one
  reference is denied, missing or fails, nothing is returned. One command can
  use at most 100 distinct references.
- `request_timeout` is capped at 140s, so the server always answers before the
  client gives up (150s).
- `opb run` uses `exec(2)` and supports Unix only.

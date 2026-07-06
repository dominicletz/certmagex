# AGENTS.md

## Cursor Cloud specific instructions

CertMagex is a single **Elixir/Mix library** (Hex package `:certmagex`), not a runnable
service or web app. It provides automatic Let's Encrypt/ZeroSSL TLS certificates via the
`sni_fun` callback. There is no dev server to start; you build, lint, test, and exercise it
from `iex`/`mix run`.

- Toolchain: Elixir + Erlang/OTP are preinstalled from apt (Elixir 1.14, OTP 25.3, matching
  the CI target in `.github/workflows/test.yml`). Hex/rebar are installed for the user.
- Standard commands (see `mix.exs`):
  - Deps: `mix deps.get`
  - Compile: `mix compile`
  - Test: `mix test` (ExUnit; self-contained and offline — no network/ACME server needed)
  - Lint: `mix lint` (alias = `compile` + `format --check-formatted` + `credo` + `dialyzer`)
- `mix lint` runs Dialyzer, which builds PLT files on the first run (roughly a minute or two).
  The PLTs are cached under `_build/`, so subsequent runs are fast. Don't assume `mix lint`
  is hung during that first PLT build.
- No `mix.lock` is committed (this is a library), so `mix deps.get` resolves the latest
  matching dependency versions each time.
- Certificates/state are stored on local disk under `$HOME/.local/share/certmagex` (DETS via
  `dets_plus`), honoring `XDG_DATA_HOME`. No external database.
- End-to-end certificate issuance (real ACME) requires a consuming Phoenix/Cowboy/Bandit app
  with ports 80/443 free and internet access; that is out of scope for this repo. The core
  SNI/storage flow can be exercised offline by inserting a self-signed cert via
  `CertMagex.insert/3` and resolving it with `CertMagex.sni_fun/1`.

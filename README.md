# CertMagex

Automatic SSL certs from Let's Encrypt for your Phoenix applications. This is based on the [ZeroSSL](https://github.com/riccardomanfrin/zerossl) library which is used for the ACME handshake. Plugging into the `sni_fun` and the name is inspired by similar functionality of the golang [certmagic](https://github.com/caddyserver/certmagic) library.

This is used in the real world for example on [https://tcpbin.net](https://tcpbin.net).

## Installation

For Cowboy add to your prod.exs:

```elixir
config <your_app>, <your_endpoint>,
  https: [port: 443, sni_fun: &CertMagex.sni_fun/1],
  # ATTENTION: Ensure you comment http: out and port 80 is free!
  ...
```

For Bandit add to your prod.exs:

```elixir
config <your_app>, <your_endpoint>,
  https: [port: 443, thousand_island_options: [transport_options: [sni_fun: &CertMagex.sni_fun/1]]],
  # ATTENTION: Ensure you comment http: out and port 80 is free!
  ...
```

And add this to your deps:

```elixir
def deps do
  [
    {:certmagex, "~> 1.0"}
  ]
end
```

You're done!

## Optional Configuration values

The following configuration values are optional and can be set in your `config.exs` file.

- `user_email`: The email to use for the ACME handshake. Let's encrypt might send informational emails to this address.
- `provider`: The provider to use for the ACME handshake. Can be `:letsencrypt` or `:zerossl`. Defaults to `:letsencrypt`.
- `account_key`: The account key to use for the ACME handshake. Required only for `:zerossl` provider.
- `addr`: The address to bind to for the ACME handshake. Defaults to `0.0.0.0` on IPv4 and `::` on IPv6.
- `storage_module`: The module to use for storage. Defaults to `CertMagex.Storage.Acmev2Adapter`. Changing the module allows storing retrieved certificates in a different storage location.
- `renewal_threshold`: The threshold for certificate renewal. Defaults to renewing certificates if they have `86_400` seconds (1 day) of validity left.

Example `config.exs`

```elixir
config :certmagex,
  provider: :zerossl,
  account_key: System.get_env("ZEROSSL_ACCOUNT_KEY"),
  addr: "0.0.0.0",
  user_email: "your@email.com",
  storage_module: CertMagex.Storage.Acmev2Adapter
```

# Notes

Generated certificates are by default stored in `$HOME/.local/share/certmagex` but the XDG_DATA_HOME variable is respected.

This wouldn't be possible without the Acmev2 module from zerossl https://hex.pm/packages/zerossl

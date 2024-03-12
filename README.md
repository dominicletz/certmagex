# CertMagex

Automatic SSL certs from Let's Encrypt for your Phoenix applications.

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
    {:certmagex, "~> 1.0.0"}
  ]
end
```

You're done!


# Notes

Generated certificates are by default stored in `$HOME/.local/share/certmagex` but the XDG_DATA_HOME variable is respected.

This wouldn't be possible without the Acmev2 module from zerossl https://hex.pm/packages/zerossl

defmodule CertMagex.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    # We're updating the default to use let's encrypt
    if Application.get_env(:zerossl, :provider) == nil do
      Application.put_env(:zerossl, :provider, :letsencrypt)
    end

    if Application.get_env(:zerossl, :storage_module) == nil do
      Application.put_env(:zerossl, :storage_module, CertMagex.Storage.Acmev2Adapter)
    end

    children = [CertMagex.Worker]
    opts = [strategy: :one_for_one, name: CertMagex.Supervisor]
    Supervisor.start_link(children, opts)
  end
end

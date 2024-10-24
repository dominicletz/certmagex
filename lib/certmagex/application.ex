defmodule CertMagex.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application
  # not real infinity, but it's a big number
  @infinity 1_000_000

  @impl true
  def start(_type, _args) do
    if Application.get_env(:certmagex, :storage_module) == nil do
      Application.put_env(:certmagex, :storage_module, CertMagex.Storage.Acmev2Adapter)
    end

    children = [CertMagex.Storage.child(), CertMagex.Worker]
    opts = [max_restarts: @infinity, strategy: :one_for_one, name: CertMagex.Supervisor]
    Supervisor.start_link(children, opts)
  end
end

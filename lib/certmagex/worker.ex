defmodule CertMagex.Worker do
  @moduledoc false
  alias CertMagex.Storage
  use GenServer, restart: :permanent
  defstruct []

  def start_link(_args) do
    GenServer.start_link(__MODULE__, :ok, name: __MODULE__)
  end

  @impl true
  def init(:ok) do
    Storage.init()
    {:ok, %__MODULE__{}}
  end

  def gen_cert(domain) do
    GenServer.call(__MODULE__, {:gen_cert, domain}, :infinity)
  end

  @impl true
  def handle_call({:gen_cert, domain}, _from, state) do
    case Storage.lookup(domain) do
      nil ->
        {cert_priv_key, public_cert} = Acmev2.gen_cert(domain)
        result = {:ok, {cert_priv_key, public_cert}}
        :ok = Storage.insert(domain, result)
        {:reply, result, state}

      result ->
        {:reply, result, state}
    end
  end
end

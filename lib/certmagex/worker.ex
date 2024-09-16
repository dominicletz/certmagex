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
    {:ok, %__MODULE__{}}
  end

  def gen_cert(domain) do
    with {:error, :rate_limit} <- GenServer.call(__MODULE__, {:gen_cert, domain}, :infinity) do
      Process.sleep(3_000)
      gen_cert(domain)
    end
  end

  def cast_gen_cert(domain) do
    GenServer.cast(__MODULE__, {:gen_cert, domain})
  end

  @impl true
  def handle_call({:gen_cert, domain}, _from, state) do
    result = lookup_domain(domain)

    if needs_renewal(result) do
      now = System.os_time(:second)
      last_request = Storage.lookup({:last_request, domain}) || 0

      if last_request + 15 > now do
        {:reply, {:error, :rate_limit}, state}
      else
        Storage.insert({:last_request, domain}, now)
        {cert_priv_key, public_cert} = Acmev2.gen_cert(domain)
        :ok = Storage.insert(domain, {:ok, {cert_priv_key, public_cert}})
        {{certs, key}, validity} = CertMagex.insert(domain, cert_priv_key, public_cert)
        {:reply, {:ok, {{certs, key}, validity}}, state}
      end
    else
      {:reply, {:ok, result}, state}
    end
  end

  @impl true
  def handle_cast({:gen_cert, domain}, state) do
    {:reply, _result, state} = handle_call({:gen_cert, domain}, nil, state)
    {:noreply, state}
  end

  def needs_renewal(nil), do: true

  def needs_renewal({{_cert, _key}, validity}) do
    now = DateTime.utc_now()
    DateTime.diff(validity, now, :second) < 86_400
  end

  def lookup_domain(domain) do
    case Storage.lookup({:cache, domain}) || Storage.lookup(domain) do
      {{cert, key}, validity} -> {{cert, key}, validity}
      {:ok, {cert_priv_key, public_cert}} -> CertMagex.insert(domain, cert_priv_key, public_cert)
      nil -> nil
    end
  end
end

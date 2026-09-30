defmodule CertMagex.Worker do
  @moduledoc false
  alias CertMagex.{Acmev2, Storage}
  require Logger
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

    reply =
      if needs_renewal(result) do
        gen_cert_with_rate_limit(domain)
      else
        {:ok, result}
      end

    {:reply, reply, state}
  end

  defp gen_cert_with_rate_limit(domain) do
    now = System.os_time(:second)
    last_request = Storage.lookup({:last_request, domain}) || 0

    cond do
      last_request + 15 > now ->
        {:error, :rate_limit}

      in_fail_backoff?(domain, now) ->
        {:error, {:acme_problem, %{type: "backoff", detail: "backing off after recent failure"}}}

      true ->
        persist_and_pack_cert(domain)
    end
  end

  defp in_fail_backoff?(domain, now) do
    case Storage.lookup({:last_fail, domain}) do
      until when is_integer(until) -> until > now
      _ -> false
    end
  end

  # Record last_request only after a full successful issuance so failed attempts
  # (e.g. cannot bind port 80) do not trigger the 15s / 3s retry loop.
  defp persist_and_pack_cert(domain) do
    case generate_cert(domain) do
      {:ok, {cert_priv_key, public_cert}} ->
        Storage.insert({:last_request, domain}, System.os_time(:second))
        Storage.delete({:last_fail, domain})
        :ok = Storage.insert(domain, {:ok, {cert_priv_key, public_cert}})
        {{certs, key}, validity} = CertMagex.insert(domain, cert_priv_key, public_cert)
        {:ok, {{certs, key}, validity}}

      {:error, reason} ->
        Storage.insert(
          {:last_fail, domain},
          System.os_time(:second) + fail_backoff_seconds(reason)
        )

        {:error, reason}
    end
  end

  defp fail_backoff_seconds({:acme_problem, problem}), do: acme_backoff_seconds(problem)
  defp fail_backoff_seconds(_), do: 300

  defp acme_backoff_seconds(%{detail: detail}) when is_binary(detail) do
    case Regex.run(~r/retry after (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/, detail) do
      [_, stamp] ->
        case NaiveDateTime.from_iso8601(String.replace(stamp, " ", "T")) do
          {:ok, ndt} ->
            max(
              60,
              min(
                DateTime.diff(DateTime.from_naive!(ndt, "Etc/UTC"), DateTime.utc_now()),
                7 * 24 * 3600
              )
            )

          _ ->
            3600
        end

      _ ->
        3600
    end
  end

  defp acme_backoff_seconds(_), do: 3600

  @impl true
  def handle_cast({:gen_cert, domain}, state) do
    {:reply, _result, state} = handle_call({:gen_cert, domain}, nil, state)
    {:noreply, state}
  end

  def needs_renewal(nil), do: true

  def needs_renewal({{_cert, _key}, validity}) do
    now = DateTime.utc_now()
    DateTime.diff(validity, now, :second) < renewal_threshold()
  end

  def renewal_threshold() do
    Application.get_env(:certmagex, :renewal_threshold, 86_400)
  end

  def lookup_domain(domain) do
    case Storage.lookup({:cache, domain}) || Storage.lookup(domain) do
      {{cert, key}, validity} -> {{cert, key}, validity}
      {:ok, {cert_priv_key, public_cert}} -> CertMagex.insert(domain, cert_priv_key, public_cert)
      nil -> nil
    end
  end

  defp generate_cert(domain) do
    case Acmev2.gen_cert(domain) do
      {:ok, {cert_priv_key, public_cert}} ->
        {:ok, {cert_priv_key, public_cert}}

      {:error, _} = err ->
        err
    end
  rescue
    error ->
      stacktrace = __STACKTRACE__

      Logger.error([
        "CertMagex: certificate generation failed for #{domain}\n",
        Exception.format(:error, error, stacktrace)
      ])

      {:error, error}
  catch
    kind, reason ->
      stacktrace = __STACKTRACE__

      Logger.error([
        "CertMagex: certificate generation failed for #{domain}\n",
        Exception.format(kind, reason, stacktrace)
      ])

      {:error, {kind, reason}}
  end
end

defmodule CertMagex.Storage do
  @moduledoc false

  # Pluggable storage backend. Defaults to the on-disk DetsPlus store
  # (`CertMagex.Storage.Dets`), so existing setups are unchanged. Provide a
  # custom backend — e.g. a database-backed, encrypted store for durability and
  # clustering — with:
  #
  #     config :certmagex, :storage_backend, MyApp.CertStorage
  #
  # A backend implements the `CertMagex.Storage.Backend` behaviour.

  defmodule Backend do
    @moduledoc """
    Behaviour for a CertMagex storage backend.

    `child/0` returns a supervisor child (or `:ignore`) started before the
    worker. The other callbacks read/write/delete arbitrary Erlang-term keys and
    values (CertMagex uses binaries like `"ec.key"` and tuples like
    `{:acmev2, key}`, `{:cache, domain}`, `{:last_request, domain}`).
    """
    @type key :: term()
    @type value :: term()

    @callback child() :: :supervisor.child_spec() | {module(), term()} | module() | :ignore
    @callback insert(key(), value()) :: any()
    @callback delete(key()) :: any()
    @callback lookup(key()) :: value() | nil
  end

  defmodule Acmev2Adapter do
    @moduledoc false
    def read(key) do
      case CertMagex.Storage.lookup({:acmev2, key}) do
        nil -> {:error, :not_found}
        value -> {:ok, value}
      end
    end

    def write(key, value) do
      CertMagex.Storage.insert({:acmev2, key}, value)
    end

    def exists?(key) do
      CertMagex.Storage.lookup({:acmev2, key}) != nil
    end
  end

  defmodule Dets do
    @moduledoc false
    @behaviour CertMagex.Storage.Backend

    @impl true
    def child() do
      File.mkdir_p!(directory())
      {DetsPlus, name: __MODULE__, file: Path.join(directory(), "storage.dets+")}
    end

    @impl true
    def insert(key, value) do
      DetsPlus.insert(__MODULE__, {key, value})
      DetsPlus.start_sync(__MODULE__)
    end

    @impl true
    def delete(key) do
      DetsPlus.delete(__MODULE__, key)
    end

    @impl true
    def lookup(key) do
      case DetsPlus.lookup(__MODULE__, key) do
        [{^key, value}] -> value
        _ -> nil
      end
    end

    defp directory() do
      share = System.get_env("XDG_DATA_HOME") || Path.join(System.get_env("HOME"), ".local/share")
      Path.join(share, "certmagex")
    end
  end

  @doc false
  def backend(), do: Application.get_env(:certmagex, :storage_backend, Dets)

  def child(), do: backend().child()
  def insert(key, value), do: backend().insert(key, value)
  def delete(key), do: backend().delete(key)
  def lookup(key), do: backend().lookup(key)
end

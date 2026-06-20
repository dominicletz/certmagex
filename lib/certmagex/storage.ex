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

    `child/0` returns a supervisor child (or `:ignore` if the backend needs no
    process). The other callbacks read/write/delete arbitrary Erlang-term keys
    and values (CertMagex uses binaries like `"ec.key"` and tuples like
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

    # DETS stores the table name in the file header, so opening an existing
    # `storage.dets+` with a different name fails (`{:error, {:name_mismatch,
    # ...}}`). Keep the historical name (`CertMagex.Storage`) — NOT `__MODULE__`
    # (which would be `CertMagex.Storage.Dets`) — so upgrades don't break.
    @name CertMagex.Storage

    @impl true
    def child() do
      File.mkdir_p!(directory())
      {DetsPlus, name: @name, file: Path.join(directory(), "storage.dets+")}
    end

    @impl true
    def insert(key, value) do
      DetsPlus.insert(@name, {key, value})
      DetsPlus.start_sync(@name)
    end

    @impl true
    def delete(key) do
      DetsPlus.delete(@name, key)
    end

    @impl true
    def lookup(key) do
      case DetsPlus.lookup(@name, key) do
        [{^key, value}] -> value
        _ -> nil
      end
    end

    defp directory() do
      share = System.get_env("XDG_DATA_HOME") || Path.join(System.get_env("HOME"), ".local/share")
      Path.join(share, "certmagex")
    end
  end

  # Placeholder child for backends that need no process of their own (those
  # whose `child/0` returns `:ignore`). `:ignore` is not a valid entry in a
  # supervisor's children list, so we wrap it in a worker that starts as
  # `:ignore` — the supervisor then simply skips it.
  defmodule EmptyWorker do
    @moduledoc false
    def start_link(_args), do: :ignore
    def child_spec(arg), do: %{id: __MODULE__, start: {__MODULE__, :start_link, [arg]}}
  end

  @doc false
  def backend(), do: Application.get_env(:certmagex, :storage_backend, Dets)

  def child() do
    case backend().child() do
      :ignore -> {EmptyWorker, []}
      spec -> spec
    end
  end

  def insert(key, value), do: backend().insert(key, value)
  def delete(key), do: backend().delete(key)
  def lookup(key), do: backend().lookup(key)
end

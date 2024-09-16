defmodule CertMagex.Storage do
  @moduledoc false

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

  def child() do
    File.mkdir_p!(directory())
    {DetsPlus, name: __MODULE__, file: Path.join(directory(), "storage.dets+")}
  end

  def insert(domain, value) do
    DetsPlus.insert(__MODULE__, {domain, value})
    DetsPlus.start_sync(__MODULE__)
  end

  def delete(domain) do
    DetsPlus.delete(__MODULE__, domain)
  end

  def lookup(domain) do
    case DetsPlus.lookup(__MODULE__, domain) do
      [{^domain, value}] -> value
      _ -> nil
    end
  end

  defp directory() do
    share = System.get_env("XDG_DATA_HOME") || Path.join(System.get_env("HOME"), ".local/share")
    Path.join(share, "certmagex")
  end
end

defmodule CertMagex do
  @moduledoc """
  Automatic SSL certs from Let's Encrypt for your Phoenix applications.

  ## Installation

  For Bandit add to your prod.exs:

  ```elixir
  config <your_app>, <your_endpoint>,
    # ATTENTION: Ensure you comment http: out and port 80 is free!
    https: [port: 443, thousand_island_options: [transport_options: [sni_fun: &CertMagex.sni_fun/1]]],
    ...
  ```

  For Cowboy add to your prod.exs:

  ```elixir
  config <your_app>, <your_endpoint>,
    # ATTENTION: Ensure you comment http: out and port 80 is free!
    https: [port: 443, transport_options: [sni_fun: &CertMagex.sni_fun/1]],
    ...
  ```
  """
  alias CertMagex.{Worker, Storage}
  require Logger

  def sni_fun(domain) when is_list(domain) do
    sni_fun(List.to_string(domain))
  end

  @doc """
  The SNI function to be used in your Phoenix or Cowboy configuration. E.g. for
  Cowboy add this to your prod.exs:

  ```elixir
  config <your_app>, <your_endpoint>,
    # ATTENTION: Ensure you comment http: out and port 80 is free!
    https: [port: 443, transport_options: [sni_fun: &CertMagex.sni_fun/1]],
    ...
  ```
  """
  def sni_fun(domain) when is_binary(domain) do
    now = DateTime.utc_now()

    case Storage.lookup({:cache, domain}) do
      {{cert, key}, validity} ->
        if div(DateTime.diff(validity, now, :second), 86_400) > 0 do
          [cert: cert, key: key]
        else
          Logger.info("CertMagex: Certificate expired for #{domain}, regenerating...")
          Storage.delete({:cache, domain})
          Storage.delete(domain)
          gen_cert(domain)
        end

      nil ->
        gen_cert(domain)
    end
  end

  defp gen_cert(domain) do
    case Storage.lookup(domain) || Worker.gen_cert(domain) do
      {:ok, {cert_priv_key, public_cert}} ->
        certs = decode_certs(public_cert)
        validity = validity_time(certs)
        key = decode_priv_key(cert_priv_key)
        Storage.insert({:cache, domain}, {{certs, key}, validity})
        [cert: certs, key: key]

      {:error, reason} ->
        Logger.error("CertMagex Error: #{inspect(reason)}")
        []
    end
  end

  defp validity_time(certs) do
    Enum.map(certs, fn bin -> :certmagex.not_after(bin) end)
    |> Enum.min()
    |> DateTime.from_gregorian_seconds()
  end

  defp decode_certs(pem) do
    for {:Certificate, bin, :not_encrypted} <- :public_key.pem_decode(pem) do
      bin
    end
  end

  defp decode_priv_key(pem) do
    {type, bin, :not_encrypted} =
      :public_key.pem_decode(pem)
      |> Enum.find(fn {type, _bin, _} ->
        type in [:RSAPrivateKey, :DSAPrivateKey, :ECPrivateKey]
      end)

    {type, bin}
  end
end

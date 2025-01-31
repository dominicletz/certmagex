defmodule CertMagex do
  @moduledoc """
  Automatic SSL certs from Let's Encrypt for your Phoenix applications.

  ## Installation

  For Cowboy add to your prod.exs:

  ```elixir
  config <your_app>, <your_endpoint>,
    # ATTENTION: Ensure you comment http: out and port 80 is free!
    https: [port: 443, sni_fun: &CertMagex.sni_fun/1],
    ...
  ```

  For Bandit add to your prod.exs:

  ```elixir
  config <your_app>, <your_endpoint>,
    # ATTENTION: Ensure you comment http: out and port 80 is free!
    https: [port: 443, thousand_island_options: [transport_options: [sni_fun: &CertMagex.sni_fun/1]]],
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
    https: [port: 443, sni_fun: &CertMagex.sni_fun/1],
    ...
  ```
  """
  def sni_fun(domain) when is_binary(domain) do
    if ip?(domain) do
      Logger.warning("CertMagex: IP address detected, skipping certificate generation")
      :undefined
    else
      cache_or_gen_cert(domain)
    end
  end

  @doc """
  Insert a certificate into the cache. Automatically detects all domains in the certificate.
  """
  def insert(cert_priv_key, public_cert) do
    {:Certificate, certbin, :not_encrypted} = :public_key.pem_decode(public_cert) |> List.first()

    for domain <- :certmagex.domains(certbin) do
      insert(List.to_string(domain), cert_priv_key, public_cert)
    end
  end

  @doc """
  Insert a certificate into the cache for a specific domain.
  """
  def insert(domain, cert_priv_key, public_cert) when is_binary(domain) do
    certs = decode_certs(public_cert)
    validity = validity_time(certs)
    key = decode_priv_key(cert_priv_key)
    Storage.insert({:cache, domain}, {{certs, key}, validity})
    {{certs, key}, validity}
  end

  defp ip?(domain) do
    case :inet.parse_address(String.to_charlist(domain)) do
      {:ok, _} -> true
      _ -> false
    end
  end

  defp cache_or_gen_cert(domain) do
    case CertMagex.Worker.lookup_domain(domain) do
      ret = {{cert, key}, validity} ->
        now = DateTime.utc_now()

        cond do
          # More than one day of validity left
          CertMagex.Worker.needs_renewal(ret) == false ->
            [cert: cert, key: key]

          # Still valid but less than one full day
          DateTime.diff(validity, now, :second) > 0 ->
            Logger.info("CertMagex: Certificate for #{domain} expires soon regenerating...")
            Worker.cast_gen_cert(domain)
            [cert: cert, key: key]

          # Expired
          true ->
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
    case Worker.gen_cert(domain) do
      {:ok, {{cert, key}, _validity}} ->
        [cert: cert, key: key]

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
      |> Enum.find(fn {type, _bin, flag} ->
        flag == :not_encrypted and
          type in [:RSAPrivateKey, :DSAPrivateKey, :ECPrivateKey, :PrivateKeyInfo]
      end)

    {type, bin}
  end
end

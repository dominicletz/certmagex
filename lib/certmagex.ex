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

  ## SNI hostname allow list (optional)

  With `sni_fun`, each TLS client SNI can trigger a certificate request. To avoid
  issuing or renewing certificates for random scan traffic, set
  `config :certmagex, :sni_allowed_hosts, ["www.example.com", "api.example.com"]`.
  When this list is non-empty, only those hostnames (compared
  case-insensitively) are handled; any other SNI returns `:undefined` and no
  ACME work runs. If unset or `[]`, all SNIs are considered (unchanged default).
  """
  alias CertMagex.{Storage, Worker}
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
    Logger.debug("CertMagex: sni_fun called with domain: #{domain}")

    if sni_host_allowlisted?(domain) do
      sni_fun_allowed(domain)
    else
      :undefined
    end
  end

  defp sni_host_allowlisted?(domain) do
    case Application.get_env(:certmagex, :sni_allowed_hosts) do
      hosts when is_list(hosts) and hosts != [] ->
        host_in_sni_list?(domain, hosts)

      _ ->
        true
    end
  end

  defp host_in_sni_list?(domain, hosts) do
    d = String.downcase(domain)
    Enum.any?(hosts, &(String.downcase(&1) == d))
  end

  defp sni_fun_allowed(domain) do
    provider = Application.get_env(:certmagex, :provider, :letsencrypt)

    if ip?(domain) and provider not in [:letsencrypt, :letsencrypt_test] do
      Logger.warning(
        "CertMagex: IP address detected, skipping (IP certs only with provider :letsencrypt or :letsencrypt_test)"
      )

      :undefined
    else
      cache_or_gen_cert(domain)
    end
  end

  @doc """
  Returns the SSL options for the given domain. This is useful for IP based SSL certificates.
  Info: https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability

  This will generate `[cert: cert, key: key]` that can merged into your existing SSL options.
  """
  def ssl_opts(domain) do
    case sni_fun(domain) do
      opts when is_list(opts) -> opts
      _ -> []
    end
  end

  @doc """
  Returns true if the given string is a valid IPv4 or IPv6 address.
  """
  def ip?(domain) when is_binary(domain) do
    case :inet.parse_address(String.to_charlist(domain)) do
      {:ok, _} -> true
      _ -> false
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

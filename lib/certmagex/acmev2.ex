defmodule CertMagex.Acmev2 do
  @moduledoc """
  Implementation of the ACMEv2 protocol for Zerossl (on Elliptic Curves cryptography)
  """

  require Logger
  require Record

  Record.defrecord(
    :ecdsa_signature,
    :"ECDSA-Sig-Value",
    Record.extract(:"ECDSA-Sig-Value", from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  Record.defrecord(
    :ecdsa_key,
    :ECPrivateKey,
    Record.extract(:ECPrivateKey, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  Record.defrecord(
    :csr,
    :TBSCertificate,
    Record.extract(:TBSCertificate, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  # @ecdsa_with_SHA256 {1, 2, 840, 10045, 4, 3, 2}

  @provider_api %{
    zerossl: "https://acme.zerossl.com/v2/DV90",
    letsencrypt: "https://acme-v02.api.letsencrypt.org/directory",
    letsencrypt_test: "https://acme-staging-v02.api.letsencrypt.org/directory"
  }

  @app :certmagex
  defp account_key(), do: Application.get_env(@app, :account_key)
  defp acme_uri(), do: @provider_api[provider()]

  defp http_addr() do
    Application.get_env(@app, :addr, nil) || if ipv6?(), do: "::", else: "0.0.0.0"
  end

  defp http_port(), do: Application.get_env(@app, :port, 80)
  defp provider(), do: Application.get_env(@app, :provider, :letsencrypt)
  defp require_external_account_binding(), do: provider() in [:zerossl]

  defp storage_module(),
    do: Application.get_env(@app, :storage_module, CertMagex.Storage.Acmev2Adapter)

  defp user_email(), do: Application.get_env(@app, :user_email)

  @doc """
  Print a certificate content
  """
  def cert_print(cert) do
    certs = :public_key.pem_decode(cert)

    for cert <- certs do
      :public_key.pem_entry_decode(cert)
    end
  end

  @doc """
  Print a JWS content
  """
  def jws_dec(data) do
    %{
      payload: payload,
      protected: protected,
      signature: signature
    } = jdec(data)

    %{
      payload: dec(payload),
      protected: dec(protected),
      signature: signature
    }
  end

  defp dec(""), do: ""

  defp dec(data),
    do:
      data
      |> bdec()
      |> jdec()

  defp bdec(data), do: Base.url_decode64!(data, padding: false)
  defp jdec(data), do: Jason.decode!(data, keys: :atoms)

  defp enc(data),
    do:
      data
      |> jenc()
      |> benc()

  defp benc(data), do: Base.url_encode64(data, padding: false)
  defp jenc(data), do: Jason.encode!(data)

  defp calcjwk() do
    ecdsa_key(publicKey: public_key) = ensure_ec_key()
    [_h | xy] = :erlang.binary_to_list(public_key)
    [x, y] = xy |> Enum.chunk_every(32)

    %{
      "crv" => "P-256",
      "kty" => "EC",
      "x" => x |> :erlang.list_to_binary() |> Base.url_encode64(padding: false),
      "y" => y |> :erlang.list_to_binary() |> Base.url_encode64(padding: false)
    }
  end

  defp ensure_ec_key() do
    # Create a generic Elliptic Curve key to use as Account Key in the ACMEv2 protocol
    # This key is associated with the user account and can be used multiple times.
    # In general the key can be used for revoking of the certificate and other operations.
    #
    # {pubkey, privkey} = :crypto.generate_key(:ecdh, :prime256v1)
    # Credits:
    # https://github.com/voltone/x509/blob/48833e38f36fa817b0988bfb2f4ead07f233c3e4/lib/x509/private_key.ex#L63
    #
    # "Note that this function uses Erlang/OTP's `:public_key` application, which
    # does not support all curve names returned by the `:crypto.ec_curves/0`
    # function. In particular, the NIST Prime curves must be selected by their
    # SECG id, e.g. NIST P-256 is `:secp256r1` rather than `:prime256v1`. Please
    # refer to [RFC4492 appendix A](https://www.rfc-editor.org/rfc/rfc4492.html#appendix-A)
    # for a mapping table."

    case storage_module().exists?("ec.key") do
      true ->
        {:ok, eckey} = storage_module().read("ec.key")
        eckey

      false ->
        key = :public_key.generate_key({:namedCurve, :secp256r1})
        pem_entry = :public_key.pem_entry_encode(:ECPrivateKey, key)
        domain_ec_key = :public_key.pem_encode([pem_entry])
        storage_module().write("ec.key", domain_ec_key)
        domain_ec_key
    end
    |> :public_key.pem_decode()
    |> hd()
    |> :public_key.pem_entry_decode()
  end

  defp es256sign(payload) do
    eckey = ensure_ec_key()
    signature = :public_key.sign(payload, :sha256, eckey)

    # Equivalent yet short version of the stuff below
    benc(signature)

    # The following part mimics acme.sh. Zerossl doesn't need this "translation",
    # but apparently letsencrypt does, therefore I'm keeping it for both

    {:"ECDSA-Sig-Value", r, s} = :public_key.der_decode(:"ECDSA-Sig-Value", signature)

    r =
      r
      |> Integer.to_string(16)
      |> String.pad_leading(64, "0")

    s =
      s
      |> Integer.to_string(16)
      |> String.pad_leading(64, "0")

    "#{r}#{s}"
    |> :binary.decode_hex()
    |> benc()
  end

  defp try_load_eab_from_file() do
    with {:ok, bin} <- storage_module().read("eab_credentials.json"),
         %{success: true} = eab_credentials <- jdec(bin) do
      eab_credentials
    else
      _ -> nil
    end
  end

  defp store_eab_to_file_and_dec(bin) do
    storage_module().write("eab_credentials.json", bin)
    jdec(bin)
  end

  @spec get_eab_credentials({:user_email | :account_key, account_key :: binary()}) ::
          map()
  defp get_eab_credentials({user_id_type, user_id}) do
    case try_load_eab_from_file() do
      nil ->
        Logger.debug("Deriving EAB credentials from #{user_id_type}")

        case user_id_type do
          :account_key ->
            {:ok, %HTTPoison.Response{body: bin, status_code: 200}} =
              post(
                "https://api.zerossl.com/acme/eab-credentials?access_key=#{user_id}",
                "",
                []
              )

            store_eab_to_file_and_dec(bin)

          :user_email ->
            {:ok, %HTTPoison.Response{body: bin, status_code: 200}} =
              post(
                "https://api.zerossl.com/acme/eab-credentials-email",
                "email=#{user_id}",
                [{"content-type", "application/x-www-form-urlencoded"}]
              )

            store_eab_to_file_and_dec(bin)
        end

      eab_credentials ->
        eab_credentials
    end

    # {nonce,
    # %{
    #  success: true,
    #  #Why this works for zerossl.sh and comes from there I don't know mine doesn't
    #  eab_kid: "taHRbdCH-vXZoUw6eo1Qwg",
    #  eab_hmac_key: "PU8DmBne_woTwhm5677xx8bvD0LILGfFJ9eJiCQT_jDSrCDQOpam6DGGY8XS-AkurBEHEQyVY9FzIkBgqF9TOg"
    # }}
  end

  defp get(uri), do: request(:get, uri)
  defp post(uri, body, headers), do: request(:post, uri, body, headers)

  defp request(method, uri, body \\ "", headers \\ [], times \\ 5) do
    case times <= 0 do
      true ->
        raise "Too many tries"

      _ ->
        try do
          {:ok, _response} = HTTPoison.request(method, uri, body, headers, recv_timeout: 10_000)
        rescue
          error ->
            Logger.info("Troubles contacting ACMEv2 provider: #{inspect(error)}")
            request(uri, method, body, headers, times - 1)
        end
    end
  end

  defp get_operations() do
    {:ok, res} = get(acme_uri())
    if res.status_code != 200, do: raise("Cannot get operations")

    jdec(res.body)
  end

  defp get_new_nonce(ops) do
    {:ok, res} = get(ops[:newNonce])
    if res.status_code != 204, do: raise("Cannot get new nonce")
    get_nonce_from_resp(res)
  end

  defp get_nonce_from_resp(res) do
    {_, nonce} = List.keyfind!(res.headers, "Replay-Nonce", 0)
    nonce
  end

  defp get_location_from_resp(res) do
    {_, location} = List.keyfind(res.headers, "Location", 0, {:error, nil})
    location
  end

  defp post_new_account(ops, nonce, eab_credentials) do
    # ****************************** PACKET2 from WIRESHARK!!! ********************************
    ## READ example HERE https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3.4
    # eab cred 2
    # {
    #   "success":true,
    #   "eab_kid":"lpsiTvsUUaX3L3Sfb4PTWQ",
    #   "eab_hmac_key":"BCX-AyjpZrAdlQCnY58QJN2J-2Jb6WbGT81AawMNxJhDfYo6tJFRf7rj4XwnbJzJQn2e9_bz6boeDW7t6WWhIg"
    #   04 25 fe 03 28 e9 66 b0 1d 9c15 a7 63 9f 10 24 dd 749 fb 62 5b e9 66 c6 4f cd 40 6b 03 0d c4 98 43 7d 8a 3a b4 360ad11 51 7f ba e3 e1 7c 27 6c 9c c9 42 7d 371e f7 f6 f3 e9 ba 1e 0d 6e ed e9 65
    # }
    # packet2
    # {
    #  "protected": "eyJub25jZSI6ICJpMDg2V3hNQ1U3ZjBFRk5vTnllUTBxZ3FKM25sMGstcFB2X2JCcU0tUjVFIiwgInVybCI6ICJodHRwczovL2FjbWUuemVyb3NzbC5jb20vdjIvRFY5MC9uZXdBY2NvdW50IiwgImFsZyI6ICJFUzI1NiIsICJqd2siOiB7ImNydiI6ICJQLTI1NiIsICJrdHkiOiAiRUMiLCAieCI6ICJtVDRlNUNwUGF4Q0wzT25pdnZtSThSTGRBZzNmX0R2QW9maWJPSTZwQW0wIiwgInkiOiAiWExMUlF5dWhCbFk0eDNpcmt4WHBXN3Jsdm5OOERNWjFJQUhSRHE5UkpWQSJ9fQ",
    #  "payload": "eyJjb250YWN0IjogWyJtYWlsdG86cmljY2FyZG9tYW5mcmluQGdtYWlsLmNvbSJdLCAidGVybXNPZlNlcnZpY2VBZ3JlZWQiOiB0cnVlLCJleHRlcm5hbEFjY291bnRCaW5kaW5nIjp7InByb3RlY3RlZCI6ImV5SmhiR2NpT2lKSVV6STFOaUlzSW10cFpDSTZJbXh3YzJsVWRuTlZWV0ZZTTB3elUyWmlORkJVVjFFaUxDSjFjbXdpT2lKb2RIUndjem92TDJGamJXVXVlbVZ5YjNOemJDNWpiMjB2ZGpJdlJGWTVNQzl1WlhkQlkyTnZkVzUwSW4wIiwgInBheWxvYWQiOiJleUpqY25ZaU9pQWlVQzB5TlRZaUxDQWlhM1I1SWpvZ0lrVkRJaXdnSW5naU9pQWliVlEwWlRWRGNGQmhlRU5NTTA5dWFYWjJiVWs0VWt4a1FXY3pabDlFZGtGdlptbGlUMGsyY0VGdE1DSXNJQ0o1SWpvZ0lsaE1URkpSZVhWb1FteFpOSGd6YVhKcmVGaHdWemR5YkhadVRqaEVUVm94U1VGSVVrUnhPVkpLVmtFaWZRIiwgInNpZ25hdHVyZSI6InpacVNMMW5FSm5tb3FRcER1VHlNVkJIM0xtbDFkZVl4U2hsSEFqbVh6azgifX0",
    #  "signature": "CDtBv2b_Wkh8P39MqqSE_A-gWFXbbOlS81UGxKkrGqI4ImNDOvwpqRJUIkcUZgkihbLpzhqbkLJfNkwL6aeu6A"
    # }
    # packet2
    # protected
    # %{
    #  "alg" => "ES256",
    #  "jwk" => %{
    #    "crv" => "P-256",
    #    "kty" => "EC",
    #    "x" => "mT4e5CpPaxCL3OnivvmI8RLdAg3f_DvAofibOI6pAm0",
    #    "y" => "XLLRQyuhBlY4x3irkxXpW7rlvnN8DMZ1IAHRDq9RJVA"
    #  },
    #  "nonce" => "i086WxMCU7f0EFNoNyeQ0qgqJ3nl0k-pPv_bBqM-R5E",
    #  "url" => "#{acme_uri()}/newAccount"
    # }
    # payload
    # %{
    #  "contact" => ["mailto:riccardomanfrin@gmail.com"],
    #  "externalAccountBinding" => %{
    #    "payload" => "eyJjcnYiOiAiUC0yNTYiLCAia3R5IjogIkVDIiwgIngiOiAibVQ0ZTVDcFBheENMM09uaXZ2bUk4UkxkQWczZl9EdkFvZmliT0k2cEFtMCIsICJ5IjogIlhMTFJReXVoQmxZNHgzaXJreFhwVzdybHZuTjhETVoxSUFIUkRxOVJKVkEifQ",
    #    "protected" => "eyJhbGciOiJIUzI1NiIsImtpZCI6Imxwc2lUdnNVVWFYM0wzU2ZiNFBUV1EiLCJ1cmwiOiJodHRwczovL2FjbWUuemVyb3NzbC5jb20vdjIvRFY5MC9uZXdBY2NvdW50In0",
    #    "signature" => "zZqSL1nEJnmoqQpDuTyMVBH3Lml1deYxShlHAjmXzk8"
    #  },
    #  "termsOfServiceAgreed" => true
    # }
    # payload.payload
    # pp = "eyJjcnYiOiAiUC0yNTYiLCAia3R5IjogIkVDIiwgIngiOiAibVQ0ZTVDcFBheENMM09uaXZ2bUk4UkxkQWczZl9EdkFvZmliT0k2cEFtMCIsICJ5IjogIlhMTFJReXVoQmxZNHgzaXJreFhwVzdybHZuTjhETVoxSUFIUkRxOVJKVkEifQ"
    # %{
    #  "crv" => "P-256",
    #  "kty" => "EC",
    #  "x" => "mT4e5CpPaxCL3OnivvmI8RLdAg3f_DvAofibOI6pAm0",
    #  "y" => "XLLRQyuhBlY4x3irkxXpW7rlvnN8DMZ1IAHRDq9RJVA"
    # }
    # payload.protected
    # pprotected ="eyJhbGciOiJIUzI1NiIsImtpZCI6Imxwc2lUdnNVVWFYM0wzU2ZiNFBUV1EiLCJ1cmwiOiJodHRwczovL2FjbWUuemVyb3NzbC5jb20vdjIvRFY5MC9uZXdBY2NvdW50In0"
    # pprotected |> Base.decode64!(padding: false) |> Jason.decode!()
    # %{
    #  "alg" => "HS256",
    #  "kid" => "lpsiTvsUUaX3L3Sfb4PTWQ",
    #  "url" => "#{acme_uri()}/newAccount"
    # }

    contact =
      case user_email() do
        nil -> []
        email -> ["mailto:#{email}"]
      end

    payload = %{
      "contact" => contact,
      "termsOfServiceAgreed" => true
    }

    payload =
      case eab_credentials do
        nil ->
          payload

        _ ->
          payload_payload =
            calcjwk()
            |> enc()

          payload_protected =
            %{
              "alg" => "HS256",
              "kid" => eab_credentials[:eab_kid],
              "url" => ops[:newAccount]
            }
            |> enc()

          hmac_key = eab_credentials[:eab_hmac_key] |> Base.url_decode64!(padding: false)
          sign_input = "#{payload_protected}.#{payload_payload}"

          hmac_signature =
            :crypto.mac(:hmac, :sha256, hmac_key, sign_input)
            |> benc()

          payload
          |> Map.put("externalAccountBinding", %{
            "payload" => payload_payload,
            "protected" => payload_protected,
            "signature" => hmac_signature
          })
      end
      |> enc()

    protected =
      %{
        "alg" => "ES256",
        "jwk" => calcjwk(),
        "nonce" => nonce,
        "url" => ops[:newAccount]
      }
      |> enc()

    body =
      %{
        "protected" => protected,
        "payload" => payload,
        "signature" => es256sign("#{protected}.#{payload}")
      }
      |> jenc()

    {:ok, %HTTPoison.Response{body: bin} = new_account_res} =
      post(ops[:newAccount], body, "Content-Type": "application/jose+json")

    if new_account_res.status_code != 200 and new_account_res.status_code != 201,
      do: raise("Cannot generate new_account: #{inspect(new_account_res)}")

    new_nonce = get_nonce_from_resp(new_account_res)
    account_location = get_location_from_resp(new_account_res)

    # <<"https://acme-staging-v02.api.letsencrypt.org/acme/acct/", account_key::binary>> =
    #  account_location |> IO.inspect()

    {new_nonce, account_location, Jason.decode!(bin, keys: :atoms)}
  end

  defp post_new_order(ops, domain, account_location, nonce) do
    protected =
      %{
        nonce: nonce,
        url: ops[:newOrder],
        alg: "ES256",
        kid: account_location
      }
      |> enc()

    payload =
      %{
        identifiers: [
          %{
            type: "dns",
            value: domain
          }
        ]
      }
      |> enc()

    b64signature = es256sign("#{protected}.#{payload}")

    body =
      %{
        protected: protected,
        payload: payload,
        signature: b64signature
      }
      |> jenc()

    {:ok, %HTTPoison.Response{body: bin} = new_order_res} =
      post(ops[:newOrder], body, "Content-Type": "application/jose+json")

    new_nonce = get_nonce_from_resp(new_order_res)
    {new_nonce, Jason.decode!(bin, keys: :atoms)}
  end

  defp post_authz(account_location, nonce, [authorization]) do
    protected =
      %{
        alg: "ES256",
        kid: account_location,
        nonce: nonce,
        url: authorization
      }
      |> enc()

    payload = ""

    body =
      %{
        protected: protected,
        payload: payload,
        signature: es256sign("#{protected}.#{payload}")
      }
      |> jenc()

    {:ok, %HTTPoison.Response{body: bin} = authz_res} =
      post(authorization, body, "Content-Type": "application/jose+json")

    new_nonce = get_nonce_from_resp(authz_res)

    %{challenges: challanges} = Jason.decode!(bin, keys: :atoms)

    [%{url: chall_uri, type: "http-01", token: token}] =
      Enum.filter(challanges, &(&1.type == "http-01"))

    {new_nonce, chall_uri, token}
  end

  defp processing_state_retry(fun, nonce, args, awaited, times \\ 10)

  defp processing_state_retry(fun, nonce, args, awaited, 0) do
    [_nonce, resp_body | _rest] = response = apply(fun, [nonce, args])

    if resp_body.status in awaited do
      response
    else
      raise "Operation failed with status: #{resp_body.status} (#{inspect(resp_body)})"
    end
  end

  defp processing_state_retry(fun, nonce, args, awaited, times) do
    [nonce, resp_body | _rest] = response = apply(fun, [nonce, args])

    if resp_body.status in awaited do
      response
    else
      Logger.debug(
        "Operation status: #{resp_body.status} (#{inspect(resp_body)}) => Retrying in 5 seconds..."
      )

      Process.sleep(5000)
      processing_state_retry(fun, nonce, args, awaited, times - 1)
    end
  end

  defp post_chall(nonce, [account_location, chall_uri]) do
    protected =
      %{
        alg: "ES256",
        kid: account_location,
        nonce: nonce,
        url: chall_uri
      }
      |> enc()

    payload = "{}" |> benc()

    body =
      %{
        protected: protected,
        payload: payload,
        signature: es256sign("#{protected}.#{payload}")
      }
      |> jenc()

    {:ok, %HTTPoison.Response{body: bin} = chall_res} =
      post(chall_uri, body, "Content-Type": "application/jose+json")

    new_nonce = get_nonce_from_resp(chall_res)
    resp_body = Jason.decode!(bin, keys: :atoms)

    [new_nonce, resp_body]
  end

  defp poll_authz(nonce, [account_location, authz_uri]) do
    protected =
      %{
        alg: "ES256",
        kid: account_location,
        nonce: nonce,
        url: authz_uri
      }
      |> enc()

    payload = ""

    body =
      %{
        protected: protected,
        payload: payload,
        signature: es256sign("#{protected}.#{payload}")
      }
      |> jenc()

    {:ok, %HTTPoison.Response{body: bin} = authz_res} =
      post(authz_uri, body, "Content-Type": "application/jose+json")

    new_nonce = get_nonce_from_resp(authz_res)
    resp_body = Jason.decode!(bin, keys: :atoms)

    [new_nonce, resp_body]
  end

  defp gen_key_authorization(token) do
    account_key = calcjwk()
    "#{token}.#{benc(thumbprint(account_key))}"
  end

  defp thumbprint(account_key) do
    :crypto.hash(:sha256, jenc(account_key))
  end

  defp ipv6?() do
    case :gen_tcp.connect({0, 0, 0, 0, 0, 0, 0, 0}, 0, []) do
      {:error, :econnrefused} ->
        true

      {:ok, port} ->
        :gen_tcp.close(port)
        true

      {:error, :eaddrnotavail} ->
        false

      {:error, :enetunreach} ->
        false

      {:error, other} ->
        Logger.warning("Unhandled ipv6 detection error: #{inspect(other)}")
        false
    end
  end

  defp serve(token) do
    base = Path.join(System.tmp_dir!(), "zerossl_httpd")
    path = Path.join(base, ".well-known/acme-challenge/#{token}")
    File.mkdir_p!(Path.dirname(path))
    File.write(path, gen_key_authorization(token))

    port = http_port()

    {:ok, bind_address} =
      http_addr()
      |> String.to_charlist()
      |> :inet.parse_address()

    ipfamily = if tuple_size(bind_address) == 4, do: :inet, else: :inet6

    {:ok, pid} =
      :inets.start(
        :httpd,
        [
          port: port,
          bind_address: bind_address,
          ipfamily: ipfamily,
          server_name: ~c"http_challenge",
          server_root: ~c"./",
          document_root: String.to_charlist(base)
        ],
        :stand_alone
      )

    pid
  end

  defp stop_serving(pid) do
    Process.unlink(pid)
    Process.exit(pid, :shutdown)
  end

  # defp gen_csr_erl() do
  #  csr(version: 0,
  # 	serialNumber: 4096,
  #  signature: {:AlgorithmIdentifier, @ecdsa_with_SHA256, :asn1_NOVALUE},
  # 	issuer: Issuer,
  # 	validity: Validity,
  # 	subject: Subject,
  # 	subjectPublicKeyInfo: SubjectPublicKeyInfo,
  # 	issuerUniqueID: :asn1_NOVALUE,
  # 	subjectUniqueID: :asn1_NOVALUE,
  # 	extensions: :asn1_NOVALUE)
  # end

  defp gen_csr(domain) do
    # {:ok, file} = :file.read_file("/home/riccardo/.acme.sh/riccardomanfrin.dynu.net_ecc/riccardomanfrin.dynu.net.csr")
    # csr = hd(:public_key.pem_decode(file))
    # |> :public_key.pem_entry_decode()
    #
    # {:CertificationRequest,
    #  {:CertificationRequestInfo, :v1,
    #    rdn,
    #    cert_req_info_subj,
    #    [
    #      attribute_pkcs10
    #    ]},
    #  cert_req_sign_alg,
    #  signature} = csr
    #  rdn
    key = X509.PrivateKey.new_ec(:secp256r1)

    # File.write("key.pem", X509.PrivateKey.to_pem(key))

    csr =
      X509.CSR.new(key, "CN=#{domain}")
      |> X509.CSR.to_der()
      |> benc()

    {X509.PrivateKey.to_pem(key), csr}
  end

  defp post_finalize(nonce, [csr, finalize_uri, account_location]) do
    payload = %{csr: csr} |> enc()

    protected =
      %{
        nonce: nonce,
        url: finalize_uri,
        alg: "ES256",
        kid: account_location
      }
      |> enc()

    body =
      %{
        protected: protected,
        payload: payload,
        signature: es256sign("#{protected}.#{payload}")
      }
      |> jenc()

    {:ok, %HTTPoison.Response{body: bin} = finalize_res} =
      post(finalize_uri, body, "Content-Type": "application/jose+json")

    new_nonce = get_nonce_from_resp(finalize_res)
    final_order_location_uri = get_location_from_resp(finalize_res)
    [new_nonce, Jason.decode!(bin, keys: :atoms), final_order_location_uri]
  end

  defp get_final_cert(nonce, certificate_uri, account_location) do
    payload = ""

    protected =
      %{
        nonce: nonce,
        url: certificate_uri,
        alg: "ES256",
        kid: account_location
      }
      |> enc()

    body =
      %{
        protected: protected,
        payload: payload,
        signature: es256sign("#{protected}.#{payload}")
      }
      |> jenc()

    {:ok, %HTTPoison.Response{body: bin}} =
      post(certificate_uri, body, "Content-Type": "application/jose+json")

    bin
  end

  defp post_final_order(nonce, [order_location_url, account_location]) do
    payload = ""

    protected =
      %{
        nonce: nonce,
        url: order_location_url,
        alg: "ES256",
        kid: account_location
      }
      |> enc()

    body =
      %{
        protected: protected,
        payload: payload,
        signature: es256sign("#{protected}.#{payload}")
      }
      |> jenc()

    {:ok, %HTTPoison.Response{body: bin} = final_order_res} =
      post(order_location_url, body, "Content-Type": "application/jose+json")

    new_nonce = get_nonce_from_resp(final_order_res)
    resp_body = Jason.decode!(bin, keys: :atoms)
    [new_nonce, resp_body]
  end

  @doc """
  Generates a certificate through ACMEv2 protocol for the specified domain.

  The following ACMEv2 providers are supported

  - `:zerossl` [*]
  - `:letsencrypt`
  - `:letsencrypt_test`

  Zerossl requires EAB (External Account Binding) prior to issue a certificate:
  you will have to register with a proper email to it. Once you've
  created an account, you can either provide the email or the account key (I've
  seen it called "access key" or "API key" around) in the configuration.
  The code tries to lookup for the email, and when not found, defaults
  to the `:account_key`. You can find your account key (called API key in zerossl)
  here:

      https://app.zerossl.com/developer


  To perform the authentication the EAB credentails must be retrieved.
  These are saved on a file `eab_credentials.json` to be reused
  for the following interactions with Zerossl service APIs

  The authentication method relies on the HTTP (not DNS). For it to work
  `gen_cert` opens a listening socket on port 80 where it serves the
  well-known file retrieved from the APIs exchange. When the procedure
  completes the socket is closed.

  By demonstrating the ownership of the site the user gets trusted by
  the Zerossl service and the certificate is emitted.

  The function returns a key and its related certificate. Those
  can be used to run a trusted HTTPs server.

  The key and certificate values are in binary encoded format and can be
  directly written on a file
  """
  @spec gen_cert(domain :: binary()) :: {key :: binary(), cert :: binary()}
  def gen_cert(domain) do
    eab_credentials =
      with {:eab_required, true} <- {:eab_required, require_external_account_binding()},
           {:user_email, user_email} <- {:user_email, user_email()},
           {:user_email, nil} <- {:user_email, user_email},
           {:account_key, account_key} <-
             {:account_key, account_key()},
           {:account_key, nil} <- {:account_key, account_key} do
        raise(
          "Cannot retrieve External Account Binding (EAB) Credentials without :user_email or :account_key conf"
        )
      else
        {:eab_required, false} ->
          nil

        {:user_email, _user_email} = user ->
          get_eab_credentials(user)

        {:account_key, _account_key} = user ->
          get_eab_credentials(user)
      end

    do_gen_cert(domain, eab_credentials)
  end

  defp do_gen_cert(domain, eab_credentials) do
    Logger.debug("Generating cert for domain #{domain}")

    Logger.debug("Get operations")
    ops = get_operations()

    Logger.debug("Get nonce")
    nonce = get_new_nonce(ops)

    Logger.debug("Check or forge ec.key")
    _eckey = ensure_ec_key()

    Logger.debug("Get new account")
    {nonce, account_location, _new_account_res} = post_new_account(ops, nonce, eab_credentials)

    Logger.debug("Get new order")
    {nonce, new_order_res} = post_new_order(ops, domain, account_location, nonce)

    Logger.debug("Get challanges (authz)")
    {nonce, chall_uri, token} = post_authz(account_location, nonce, new_order_res.authorizations)

    Logger.debug("Serving well known challenge token")
    pid = serve(token)

    Logger.debug("Asking to challenge http.1")
    [nonce, %{token: ^token}] = post_chall(nonce, [account_location, chall_uri])

    Logger.debug("Checking challenge http.1 validity")

    [nonce, _authz_response] =
      processing_state_retry(
        &poll_authz/2,
        nonce,
        [account_location, new_order_res.authorizations |> hd],
        ["valid"]
      )

    Logger.debug("Challenge http.1 checking valid")

    Logger.debug("Finalizing order")
    {cert_priv_key, csr} = gen_csr(domain)

    [nonce, _body, final_order_location_uri] =
      processing_state_retry(
        &post_finalize/2,
        nonce,
        [csr, new_order_res.finalize, account_location],
        ["processing", "valid"]
      )

    Process.sleep(15)

    Logger.debug("Get final certificate URL")

    [nonce, response] =
      processing_state_retry(
        &post_final_order/2,
        nonce,
        [
          final_order_location_uri,
          account_location
        ],
        ["valid"]
      )

    Logger.debug("Getting certificate")

    public_cert = get_final_cert(nonce, response.certificate, account_location)

    stop_serving(pid)

    {cert_priv_key, public_cert}
    # Now you can
    # File.write("cert.pem", public_cert)
    # File.write("key.pem", cert_priv_key)
  end
end

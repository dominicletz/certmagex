defmodule CertMagexTest.AgentBackend do
  @behaviour CertMagex.Storage.Backend
  @agent __MODULE__

  @impl true
  def child, do: {Agent, fn -> %{} end, name: @agent}

  @impl true
  def insert(key, value) do
    Agent.update(@agent, fn map -> Map.put(map, key, value) end)
    :ok
  end

  @impl true
  def delete(key) do
    Agent.update(@agent, fn map -> Map.delete(map, key) end)
  end

  @impl true
  def lookup(key) do
    Agent.get(@agent, fn map -> Map.get(map, key) end)
  end
end

defmodule CertMagexTest.IgnoreBackend do
  @behaviour CertMagex.Storage.Backend

  @impl true
  def child, do: :ignore

  @impl true
  def insert(_key, _value), do: :ok

  @impl true
  def delete(_key), do: :ok

  @impl true
  def lookup(_key), do: nil
end

defmodule CertMagexTest do
  use ExUnit.Case, async: false
  doctest CertMagex

  defp with_storage_backend(backend, fun) do
    previous = Application.get_env(:certmagex, :storage_backend)
    Application.put_env(:certmagex, :storage_backend, backend)

    on_exit(fn ->
      if previous,
        do: Application.put_env(:certmagex, :storage_backend, previous),
        else: Application.delete_env(:certmagex, :storage_backend)
    end)

    fun.()
  end

  describe "sni_fun/1 and :sni_allowed_hosts" do
    test "returns :undefined when the hostname is not in the allow list" do
      previous = Application.get_env(:certmagex, :sni_allowed_hosts)
      Application.put_env(:certmagex, :sni_allowed_hosts, ["good.example.com"])

      on_exit(fn ->
        if previous,
          do: Application.put_env(:certmagex, :sni_allowed_hosts, previous),
          else: Application.delete_env(:certmagex, :sni_allowed_hosts)
      end)

      assert :undefined = CertMagex.sni_fun("scanner.example.com")
    end
  end

  describe "ip?/1" do
    test "returns true for IPv4 addresses" do
      assert CertMagex.ip?("192.168.1.1") == true
      assert CertMagex.ip?("0.0.0.0") == true
    end

    test "returns true for IPv6 addresses" do
      assert CertMagex.ip?("::1") == true
      assert CertMagex.ip?("2001:db8::1") == true
    end

    test "returns false for domain names" do
      assert CertMagex.ip?("example.com") == false
      assert CertMagex.ip?("sub.example.com") == false
    end
  end

  describe "Acmev2.gen_cert/1 with IP identifier" do
    test "raises when provider is zerossl" do
      Application.put_env(:certmagex, :provider, :zerossl)

      assert_raise RuntimeError, ~r/IP certificates are only supported/, fn ->
        CertMagex.Acmev2.gen_cert("192.168.1.1")
      end
    after
      Application.put_env(:certmagex, :provider, :letsencrypt)
    end
  end

  describe "Worker.gen_cert/1" do
    test "reports generation errors without crashing the worker" do
      previous = Application.get_env(:certmagex, :provider)
      domain = "192.0.2.250"

      on_exit(fn ->
        if previous,
          do: Application.put_env(:certmagex, :provider, previous),
          else: Application.delete_env(:certmagex, :provider)
      end)

      Application.put_env(:certmagex, :provider, :zerossl)
      CertMagex.Storage.delete({:cache, domain})
      CertMagex.Storage.delete(domain)

      assert {:error, %RuntimeError{message: message}} = CertMagex.Worker.gen_cert(domain)
      assert message =~ "IP certificates are only supported"
      assert %CertMagex.Worker{} = :sys.get_state(CertMagex.Worker)
    end
  end

  describe "Storage pluggable backend" do
    test "Dets backend keeps historical DETS table name for upgrades" do
      assert {DetsPlus, opts} = CertMagex.Storage.Dets.child()
      assert opts[:name] == CertMagex.Storage
    end

    test "insert/lookup/delete delegate to configured backend" do
      with_storage_backend(CertMagexTest.AgentBackend, fn ->
        {:ok, pid} = Agent.start_link(fn -> %{} end, name: CertMagexTest.AgentBackend)
        on_exit(fn -> if Process.alive?(pid), do: Agent.stop(pid, :normal) end)

        assert :ok = CertMagex.Storage.insert("ec.key", "secret")
        assert "secret" = CertMagex.Storage.lookup("ec.key")
        CertMagex.Storage.delete("ec.key")
        assert CertMagex.Storage.lookup("ec.key") == nil
      end)
    end

    test "backend child/0 returning :ignore yields EmptyWorker child spec" do
      with_storage_backend(CertMagexTest.IgnoreBackend, fn ->
        assert {CertMagex.Storage.EmptyWorker, []} = CertMagex.Storage.child()
      end)
    end
  end

  describe "IP SAN CSR generation" do
    defp ip_string_to_binary!(ip_string) do
      case :inet.parse_address(String.to_charlist(ip_string)) do
        {:ok, {a, b, c, d}} ->
          <<a, b, c, d>>

        {:ok, {a, b, c, d, e, f, g, h}} ->
          <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>

        _ ->
          raise "Invalid IP address: #{inspect(ip_string)}"
      end
    end

    test "accepts iPAddress SAN for IPv4" do
      key = X509.PrivateKey.new_ec(:secp256r1)
      ip_octets = ip_string_to_binary!("192.0.2.1") |> :binary.bin_to_list()
      san = X509.Certificate.Extension.subject_alt_name([{:iPAddress, ip_octets}])

      assert is_binary(
               X509.CSR.new(key, "CN=", extension_request: [san])
               |> X509.CSR.to_der()
             )
    end

    test "accepts iPAddress SAN for IPv6" do
      key = X509.PrivateKey.new_ec(:secp256r1)
      ip_octets = ip_string_to_binary!("2001:db8::1") |> :binary.bin_to_list()
      san = X509.Certificate.Extension.subject_alt_name([{:iPAddress, ip_octets}])

      assert is_binary(
               X509.CSR.new(key, "CN=", extension_request: [san])
               |> X509.CSR.to_der()
             )
    end
  end
end

defmodule CertMagexTest do
  use ExUnit.Case, async: false
  doctest CertMagex

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

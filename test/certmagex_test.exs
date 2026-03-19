defmodule CertMagexTest do
  use ExUnit.Case
  doctest CertMagex

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
end

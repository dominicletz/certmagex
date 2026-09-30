defmodule CertMagex.WorkerBackoffTest do
  use ExUnit.Case, async: false

  @domain "192.0.2.251"

  setup do
    previous = Application.get_env(:certmagex, :provider)
    Application.put_env(:certmagex, :provider, :zerossl)

    CertMagex.Storage.delete({:cache, @domain})
    CertMagex.Storage.delete(@domain)
    CertMagex.Storage.delete({:last_fail, @domain})
    CertMagex.Storage.delete({:last_request, @domain})

    on_exit(fn ->
      if previous,
        do: Application.put_env(:certmagex, :provider, previous),
        else: Application.delete_env(:certmagex, :provider)

      CertMagex.Storage.delete({:cache, @domain})
      CertMagex.Storage.delete(@domain)
      CertMagex.Storage.delete({:last_fail, @domain})
      CertMagex.Storage.delete({:last_request, @domain})
    end)

    :ok
  end

  test "failed issuance backs off and second call does not retry ACME" do
    assert {:error, %RuntimeError{}} = CertMagex.Worker.gen_cert(@domain)

    until = CertMagex.Storage.lookup({:last_fail, @domain})
    assert is_integer(until)
    assert until > System.os_time(:second)

    {micros, second} = :timer.tc(fn -> CertMagex.Worker.gen_cert(@domain) end)

    assert {:error, {:acme_problem, %{type: "backoff"}}} = second
    assert micros < 1_000_000
  end

  test "successful issuance clears a prior fail backoff" do
    CertMagex.Storage.insert({:last_fail, @domain}, System.os_time(:second) - 10)
    CertMagex.Storage.delete({:last_fail, @domain})

    assert CertMagex.Storage.lookup({:last_fail, @domain}) == nil
  end
end

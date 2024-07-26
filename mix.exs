defmodule CertMagex.MixProject do
  use Mix.Project

  @version "1.0.4"
  @name "CertMagex"
  @url "https://github.com/dominicletz/certmagex"
  @maintainers ["Dominic Letz"]

  def project do
    [
      app: :certmagex,
      elixir: "~> 1.13",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      name: @name,
      version: @version,
      docs: docs(),
      package: package(),
      homepage_url: @url,
      aliases: aliases(),
      description:
        "Automatic Letsencrypt certificates for your ssl sockets and https phoenix apps",
      dialyzer: [plt_add_apps: [:zerossl]]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :inets],
      mod: {CertMagex.Application, []},
      included_applications: [:zerossl]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:zerossl, "~> 1.0", runtime: false},
      {:dets_plus, "~> 2.1"},
      {:httpoison, "~> 2.0"},
      {:ex_doc, "~> 0.28", only: :dev, runtime: false},
      {:credo, "~> 1.6", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.2", only: [:dev], runtime: false}
    ]
  end

  defp aliases() do
    [
      lint: [
        "compile",
        "format --check-formatted",
        "credo",
        "dialyzer"
      ]
    ]
  end

  defp docs do
    [
      main: @name,
      source_ref: "v#{@version}",
      source_url: @url,
      authors: @maintainers
    ]
  end

  defp package do
    [
      maintainers: @maintainers,
      licenses: ["MIT"],
      links: %{github: @url},
      files: ~w(lib src LICENSE.md mix.exs README.md)
    ]
  end
end

# frozen_string_literal: true

# Released under the Apache License, Version 2.0.
# Copyright, 2026, by General Intelligence Systems.

require_relative "lib/vodozemac/version"

Gem::Specification.new do |spec|
  spec.name = "vodozemac"
  spec.version = Vodozemac::VERSION
  spec.authors = ["Nathan Kidd"]
  spec.email = ["nathankidd@hey.com"]
  spec.license = "Apache-2.0"

  spec.summary = "Ruby bindings for vodozemac, the Rust Olm and Megolm implementation."
  spec.description = "Olm and Megolm for Ruby, over the vodozemac crate by magnus. Accounts, sessions, " \
    "group sessions, short authentication strings, the ed25519 and curve25519 key types and " \
    "PkEncryption, with every key and ciphertext crossing the boundary as base64."
  spec.homepage = "https://github.com/n-at-han-k/vodozemac-rb"

  spec.required_ruby_version = ">= 3.3"

  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["documentation_uri"] = "https://n-at-han-k.github.io/vodozemac-rb/"

  # The library, and the native extension's sources.
  #
  # The crate ships because spec.extensions builds it at install time from the source gem, and Cargo.toml and Cargo.lock ship with it because they are the workspace root rb_sys runs `cargo metadata` from. A precompiled platform gem carries the built object instead, and builds nothing.
  #
  # The built object is rejected: `rake compile` installs one into lib/vodozemac, and that one belongs to this machine's Ruby. The source gem compiles its own, and rake-compiler puts the right one into each precompiled gem itself.
  #
  # LICENSE and NOTICE ship because the Apache License asks for both: section 4(a) wants every recipient given a copy of the licence, and 4(d) wants the attribution notices carried along with it.
  spec.files = Dir.glob(
    ["{lib}/**/*", "{ext}/**/*.{rs,rb,toml}", "Cargo.toml", "Cargo.lock", "LICENSE", "NOTICE", "README.md", "CHANGELOG.md"],
    File::FNM_DOTMATCH,
    base: __dir__,
  ).reject{|path| File.fnmatch?("*.{so,bundle,dll,o,a}", path, File::FNM_EXTGLOB)}

  spec.require_paths = ["lib"]
  spec.extensions = ["ext/vodozemac/extconf.rb"]

  # GemKit::Deprecate declares a deprecation as a dated promise: the replacement, and the version the old name stops existing in.
  spec.add_dependency "gem_kit", "~> 0.2"

  # Wanted at install time rather than only in development: ext/vodozemac/extconf.rb requires rb_sys/mkmf, so installing the source gem resolves this before it can compile.
  spec.add_dependency "rb_sys", "~> 0.9"

  # The Rakefile's RbSys::ExtensionTask, which `rake compile` and the cross-compile workflow drive.
  spec.add_development_dependency "rake-compiler", "~> 1.3"
  spec.add_development_dependency "lefthook", "~> 2.2"
end

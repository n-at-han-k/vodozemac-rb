# frozen_string_literal: true

# Released under the Apache License, Version 2.0.
# Copyright, 2026, by General Intelligence Systems.

require_relative "vodozemac/version"

# The native extension, which is where every class in this module is defined.
#
# A precompiled platform gem carries one object per Ruby ABI, which rake-compiler puts under lib/vodozemac/3.3, 3.4 and so on. The source gem compiles one object and installs it beside the library, which is also where `rake compile` puts it.
begin
  require_relative "vodozemac/#{RUBY_VERSION[/\d+\.\d+/]}/vodozemac"
rescue LoadError
  require_relative "vodozemac/vodozemac"
end

# Ruby bindings for vodozemac, the Rust Olm and Megolm implementation.
#
# Every key and every ciphertext crossing this boundary is a base64 string, because that is how Matrix moves them.
module Vodozemac
end

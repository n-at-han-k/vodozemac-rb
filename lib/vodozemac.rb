# frozen_string_literal: true

# Released under the Apache License, Version 2.0.
# Copyright, 2026, by General Intelligence Systems.

require_relative "vodozemac/version"

# The native extension, which is where every class in this module is defined.
require_relative "vodozemac/vodozemac"

# Ruby bindings for vodozemac, the Rust Olm and Megolm implementation.
#
# Every key and every ciphertext crossing this boundary is a base64 string, because that is how Matrix moves them.
module Vodozemac
end

# frozen_string_literal: true

# Released under the Apache License, Version 2.0.
# Copyright, 2026, by General Intelligence Systems.

require "vodozemac/version"

describe Vodozemac do
  it "has a version" do
    expect(Vodozemac::VERSION).to be =~ /\A\d+\.\d+\.\d+\z/
  end
end

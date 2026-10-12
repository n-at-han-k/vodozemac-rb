# frozen_string_literal: true

# Released under the Apache License, Version 2.0.
# Copyright, 2026, by General Intelligence Systems.

require "vodozemac"

describe Vodozemac::Curve25519SecretKey do
  let(:key) {Vodozemac::Curve25519SecretKey.new}

  it "has a private half and a public half" do
    expect(key.to_base64).to be_a(String)
    expect(key.public_key).to be_a(String)
  end

  it "round trips through base64" do
    restored = Vodozemac::Curve25519SecretKey.from_base64(key.to_base64)

    expect(restored.public_key).to be == key.public_key
  end

  it "agrees the same secret from either side" do
    theirs = Vodozemac::Curve25519SecretKey.new

    expect(key.diffie_hellman(theirs.public_key)).to be == theirs.diffie_hellman(key.public_key)
  end

  it "refuses a private half which is not 32 bytes" do
    expect do
      Vodozemac::Curve25519SecretKey.from_base64("AAAA")
    end.to raise_exception(RuntimeError, message: be =~ /32 bytes/)
  end

  it "refuses a private half which is not base64" do
    expect{Vodozemac::Curve25519SecretKey.from_base64("not base64!")}.to raise_exception(RuntimeError)
  end

  it "refuses a public half which is not a key" do
    expect{key.diffie_hellman("not-a-key")}.to raise_exception(RuntimeError)
  end
end

describe Vodozemac::Curve25519PublicKey do
  let(:secret) {Vodozemac::Curve25519SecretKey.new}

  it "round trips through base64" do
    public_key = Vodozemac::Curve25519PublicKey.from_base64(secret.public_key)

    expect(public_key.to_base64).to be == secret.public_key
  end

  it "refuses a string which is not a key" do
    expect{Vodozemac::Curve25519PublicKey.from_base64("short")}.to raise_exception(RuntimeError)
  end
end

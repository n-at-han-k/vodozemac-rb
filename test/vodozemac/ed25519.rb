# frozen_string_literal: true

# Released under the Apache License, Version 2.0.
# Copyright, 2026, by General Intelligence Systems.

require "vodozemac"

describe Vodozemac::Ed25519SecretKey do
  let(:key) {Vodozemac::Ed25519SecretKey.new}

  it "has a private half and a public half" do
    expect(key.to_base64).to be_a(String)
    expect(key.public_key).to be_a(String)
  end

  it "round trips through base64" do
    restored = Vodozemac::Ed25519SecretKey.from_base64(key.to_base64)

    expect(restored.public_key).to be == key.public_key
  end

  it "signs a message its public half verifies" do
    signature = key.sign("hello")

    expect(Vodozemac.verify_signature(key.public_key, "hello", signature)).to be == true
  end

  it "signs the same message the same way after a round trip" do
    restored = Vodozemac::Ed25519SecretKey.from_base64(key.to_base64)

    expect(restored.sign("hello")).to be == key.sign("hello")
  end

  it "refuses a private half which is not a key" do
    expect{Vodozemac::Ed25519SecretKey.from_base64("short")}.to raise_exception(RuntimeError)
  end
end

describe Vodozemac::Ed25519Keypair do
  let(:keypair) {Vodozemac::Ed25519Keypair.new}

  it "has a public half" do
    expect(keypair.public_key).to be_a(String)
  end

  it "signs a message its public half verifies" do
    signature = keypair.sign("hello")

    expect(Vodozemac.verify_signature(keypair.public_key, "hello", signature)).to be == true
  end
end

describe Vodozemac::Ed25519PublicKey do
  let(:secret) {Vodozemac::Ed25519SecretKey.new}
  let(:public_key) {Vodozemac::Ed25519PublicKey.from_base64(secret.public_key)}

  it "round trips through base64" do
    expect(public_key.to_base64).to be == secret.public_key
  end

  it "verifies a signature the private half wrote" do
    expect(public_key.verify("hello", secret.sign("hello"))).to be == true
  end

  it "refuses a signature over a different message" do
    expect(public_key.verify("goodbye", secret.sign("hello"))).to be == false
  end

  it "refuses a signature from another key" do
    other = Vodozemac::Ed25519SecretKey.new

    expect(public_key.verify("hello", other.sign("hello"))).to be == false
  end

  it "refuses a key which is not a key" do
    expect{Vodozemac::Ed25519PublicKey.from_base64("short")}.to raise_exception(RuntimeError)
  end

  it "refuses a signature which is not a signature" do
    expect{public_key.verify("hello", "short")}.to raise_exception(RuntimeError)
  end
end

describe Vodozemac::Ed25519Signature do
  let(:secret) {Vodozemac::Ed25519SecretKey.new}

  it "round trips through base64" do
    signature = secret.sign("hello")

    expect(Vodozemac::Ed25519Signature.from_base64(signature).to_base64).to be == signature
  end

  it "refuses a string which is not a signature" do
    expect{Vodozemac::Ed25519Signature.from_base64("short")}.to raise_exception(RuntimeError)
  end
end

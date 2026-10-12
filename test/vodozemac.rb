# frozen_string_literal: true

# Released under the Apache License, Version 2.0.
# Copyright, 2026, by General Intelligence Systems.

require "vodozemac"

describe Vodozemac do
  it "defines every class the crate's init names" do
    required = [
      :Account, :Session, :GroupSession, :InboundGroupSession,
      :Sas, :EstablishedSas,
      :Ed25519SecretKey, :Ed25519Keypair, :Ed25519PublicKey, :Ed25519Signature,
      :Curve25519SecretKey, :Curve25519PublicKey,
      :PkDecryption, :PkEncryption,
    ]

    expect(required - Vodozemac.constants).to be(:empty?)
  end

  it "says which vodozemac it was built against" do
    expect(Vodozemac::NATIVE_VERSION).to be =~ /\A\d+\.\d+\.\d+/
  end

  it "verifies a signature an account wrote" do
    account = Vodozemac::Account.new
    signature = account.sign("hello")

    expect(Vodozemac.verify_signature(account.ed25519_key, "hello", signature)).to be == true
  end

  it "refuses a signature over a different message" do
    account = Vodozemac::Account.new
    signature = account.sign("hello")

    expect(Vodozemac.verify_signature(account.ed25519_key, "goodbye", signature)).to be == false
  end

  it "refuses a signature from a different key" do
    signature = Vodozemac::Account.new.sign("hello")

    expect(Vodozemac.verify_signature(Vodozemac::Account.new.ed25519_key, "hello", signature)).to be == false
  end
end

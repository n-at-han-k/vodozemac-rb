# frozen_string_literal: true

# Released under the Apache License, Version 2.0.
# Copyright, 2026, by General Intelligence Systems.

require "vodozemac"

describe Vodozemac::PkDecryption do
  let(:decryption) {Vodozemac::PkDecryption.new}
  let(:encryption) {Vodozemac::PkEncryption.from_base64(decryption.public_key)}

  it "has a private half and a public half" do
    expect(decryption.public_key).to be_a(String)
    expect(decryption.secret_key).to be_a(String)
  end

  it "reopens from its private half" do
    restored = Vodozemac::PkDecryption.from_base64(decryption.secret_key)

    expect(restored.public_key).to be == decryption.public_key
  end

  it "reads what was sealed to its public half" do
    ciphertext, mac, ephemeral = encryption.encrypt("hello")

    expect(decryption.decrypt(ciphertext, mac, ephemeral)).to be == "hello"
  end

  it "reads what was sealed to a copy reopened from the private half" do
    ciphertext, mac, ephemeral = encryption.encrypt("hello")
    restored = Vodozemac::PkDecryption.from_base64(decryption.secret_key)

    expect(restored.decrypt(ciphertext, mac, ephemeral)).to be == "hello"
  end

  it "cannot read what was sealed to another key" do
    other = Vodozemac::PkEncryption.from_base64(Vodozemac::PkDecryption.new.public_key)
    ciphertext, mac, ephemeral = other.encrypt("hello")

    expect{decryption.decrypt(ciphertext, mac, ephemeral)}.to raise_exception(RuntimeError)
  end

  it "refuses a private half which is not 32 bytes" do
    expect do
      Vodozemac::PkDecryption.from_base64("AAAA")
    end.to raise_exception(RuntimeError, message: be =~ /32 bytes/)
  end

  it "refuses a private half which is not base64" do
    expect{Vodozemac::PkDecryption.from_base64("not base64!")}.to raise_exception(RuntimeError)
  end

  it "refuses a message whose parts are not base64" do
    expect{decryption.decrypt("not base64!", "AAAA", "AAAA")}.to raise_exception(RuntimeError)
  end
end

describe Vodozemac::PkEncryption do
  let(:decryption) {Vodozemac::PkDecryption.new}
  let(:encryption) {Vodozemac::PkEncryption.from_base64(decryption.public_key)}

  it "seals a message into three parts" do
    ciphertext, mac, ephemeral = encryption.encrypt("hello")

    expect(ciphertext).to be_a(String)
    expect(mac).to be_a(String)
    expect(ephemeral).to be_a(String)
  end

  it "uses a fresh ephemeral key every time" do
    _one, _mac, first = encryption.encrypt("hello")
    _two, _mac, second = encryption.encrypt("hello")

    expect(first).not.to be == second
  end

  # libolm computed the MAC over the empty string rather than the ciphertext, and every
  # implementation reproduces the bug. So the same key always writes the same MAC, whatever
  # the message, which is why a backup is not authenticated. See MSC4048.
  it "writes a MAC which says nothing about the message" do
    _one, first, _ephemeral = encryption.encrypt("hello")
    _two, second, _ephemeral = encryption.encrypt("something else entirely")

    expect(first.size).to be > 0
    expect(second.size).to be == first.size
  end

  it "refuses a public half which is not a key" do
    expect{Vodozemac::PkEncryption.from_base64("short")}.to raise_exception(RuntimeError)
  end
end

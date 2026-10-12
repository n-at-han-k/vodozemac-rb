# frozen_string_literal: true

# Released under the Apache License, Version 2.0.
# Copyright, 2026, by General Intelligence Systems.

require "vodozemac"

describe Vodozemac::Sas do
  # Both halves of one verification, which is the only arrangement that agrees on anything.
  def established
    alice = Vodozemac::Sas.new
    bob = Vodozemac::Sas.new

    [alice.diffie_hellman(bob.public_key), bob.diffie_hellman(alice.public_key)]
  end

  it "has an ephemeral public key to send" do
    expect(Vodozemac::Sas.new.public_key).to be_a(String)
  end

  it "is consumed by the exchange, and refuses a second one" do
    sas = Vodozemac::Sas.new
    sas.diffie_hellman(Vodozemac::Sas.new.public_key)

    expect do
      sas.diffie_hellman(Vodozemac::Sas.new.public_key)
    end.to raise_exception(RuntimeError, message: be =~ /already been established/)
  end

  it "refuses a key which is not a curve25519 key" do
    expect{Vodozemac::Sas.new.diffie_hellman("not-a-key")}.to raise_exception(RuntimeError)
  end
end

describe Vodozemac::EstablishedSas do
  let(:info) {"MATRIX_KEY_VERIFICATION_SAS"}

  def established
    alice = Vodozemac::Sas.new
    bob = Vodozemac::Sas.new

    [alice.diffie_hellman(bob.public_key), bob.diffie_hellman(alice.public_key)]
  end

  it "carries both public keys, which the info strings are built from" do
    ours, theirs = self.established

    expect(ours.our_public_key).to be == theirs.their_public_key
    expect(ours.their_public_key).to be == theirs.our_public_key
  end

  it "agrees three decimals on both sides" do
    ours, theirs = self.established

    expect(ours.decimals(info)).to be == theirs.decimals(info)
    expect(ours.decimals(info).size).to be == 3
  end

  it "offsets the decimals by a thousand, as the specification asks" do
    ours, _theirs = self.established

    ours.decimals(info).each do |decimal|
      expect(decimal).to be >= 1000
      expect(decimal).to be <= 9191
    end
  end

  it "agrees seven emoji indices on both sides" do
    ours, theirs = self.established

    expect(ours.emoji_indices(info)).to be == theirs.emoji_indices(info)
    expect(ours.emoji_indices(info).size).to be == 7
  end

  it "keeps every emoji index inside the table" do
    ours, _theirs = self.established

    ours.emoji_indices(info).each do |index|
      expect(index).to be < 64
    end
  end

  it "agrees six raw bytes on both sides" do
    ours, theirs = self.established

    expect(ours.bytes(info)).to be == theirs.bytes(info)
    expect(ours.bytes(info).size).to be == 6
  end

  it "expands as many bytes as a method asks for" do
    ours, theirs = self.established

    expect(ours.bytes_raw(info, 16)).to be == theirs.bytes_raw(info, 16)
    expect(ours.bytes_raw(info, 16).size).to be == 16
  end

  it "refuses to expand more bytes than the hash will yield" do
    ours, _theirs = self.established

    expect(ours.bytes_raw(info, 8160).size).to be == 8160
    expect{ours.bytes_raw(info, 8161)}.to raise_exception(RuntimeError)
  end

  it "disagrees with a third party" do
    ours, _theirs = self.established
    other, _ = self.established

    expect(ours.decimals(info)).not.to be == other.decimals(info)
  end

  it "verifies a MAC the other side wrote" do
    ours, theirs = self.established
    mac = theirs.calculate_mac("ed25519:DEVICE", info)

    expect(ours.verify_mac("ed25519:DEVICE", info, mac)).to be == true
  end

  it "refuses a MAC over different input" do
    ours, theirs = self.established
    mac = theirs.calculate_mac("ed25519:DEVICE", info)

    expect(ours.verify_mac("ed25519:OTHER", info, mac)).to be == false
  end

  it "refuses a MAC under a different info string" do
    ours, theirs = self.established
    mac = theirs.calculate_mac("ed25519:DEVICE", info)

    expect(ours.verify_mac("ed25519:DEVICE", "OTHER_INFO", mac)).to be == false
  end

  # libolm padded the base64 wrongly, and the specification kept the bug as its own method name.
  it "writes the MAC libolm wrote too" do
    ours, theirs = self.established

    expect(ours.calculate_mac_invalid_base64("ed25519:DEVICE", info))
      .to be == theirs.calculate_mac_invalid_base64("ed25519:DEVICE", info)
  end

  it "refuses a MAC which is not base64" do
    ours, _theirs = self.established

    expect{ours.verify_mac("ed25519:DEVICE", info, "not base64!")}.to raise_exception(RuntimeError)
  end
end

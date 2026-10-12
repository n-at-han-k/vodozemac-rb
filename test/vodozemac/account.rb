# frozen_string_literal: true

# Released under the Apache License, Version 2.0.
# Copyright, 2026, by General Intelligence Systems.

require "vodozemac"

describe Vodozemac::Account do
  let(:account) {Vodozemac::Account.new}
  let(:pickle_key) {"0123456789abcdef0123456789abcdef"}

  it "has a pair of identity keys" do
    expect(account.ed25519_key).to be_a(String)
    expect(account.curve25519_key).to be_a(String)
  end

  it "holds no one time keys until asked" do
    expect(account.one_time_keys).to be(:empty?)
    expect(account.stored_one_time_key_count).to be == 0
  end

  it "generates one time keys, named by their own ID" do
    account.generate_one_time_keys(5)

    expect(account.one_time_keys.size).to be == 5
    expect(account.stored_one_time_key_count).to be == 5
  end

  it "forgets the one time keys once they are published" do
    account.generate_one_time_keys(3)
    account.mark_keys_as_published

    expect(account.one_time_keys).to be(:empty?)
  end

  it "says how many one time keys a server will hold" do
    expect(account.max_number_of_one_time_keys).to be > 0
  end

  it "generates a fallback key" do
    expect(account.fallback_key).to be(:empty?)

    account.generate_fallback_key

    expect(account.fallback_key.size).to be == 1
  end

  it "has no previous fallback key to forget at first" do
    expect(account.forget_fallback_key).to be == false
  end

  it "forgets the previous fallback key once a second is generated" do
    account.generate_fallback_key
    account.generate_fallback_key

    expect(account.forget_fallback_key).to be == true
  end

  it "signs a message with its own ed25519 key" do
    signature = account.sign("hello")

    expect(Vodozemac.verify_signature(account.ed25519_key, "hello", signature)).to be == true
  end

  it "survives a pickle" do
    restored = Vodozemac::Account.from_pickle(account.pickle(pickle_key), pickle_key)

    expect(restored.ed25519_key).to be == account.ed25519_key
    expect(restored.curve25519_key).to be == account.curve25519_key
  end

  it "refuses a pickle key which is not 32 bytes" do
    expect{account.pickle("short")}.to raise_exception(RuntimeError, message: be =~ /32 bytes/)
  end

  it "refuses a pickle written with another key" do
    pickled = account.pickle(pickle_key)

    expect do
      Vodozemac::Account.from_pickle(pickled, "ffffffffffffffffffffffffffffffff")
    end.to raise_exception(RuntimeError)
  end

  it "opens an outbound session to a peer's claimed keys" do
    peer = Vodozemac::Account.new
    peer.generate_one_time_keys(1)
    one_time_key = peer.one_time_keys.values.first

    session = account.create_outbound_session(peer.curve25519_key, one_time_key)

    expect(session).to be_a(Vodozemac::Session)
    expect(session.session_id).to be_a(String)
  end

  it "refuses a one time key which is not a curve25519 key" do
    peer = Vodozemac::Account.new

    expect do
      account.create_outbound_session(peer.curve25519_key, "not-a-key")
    end.to raise_exception(RuntimeError)
  end

  it "accepts an inbound session from a pre-key message, and the plaintext with it" do
    peer = Vodozemac::Account.new
    peer.generate_one_time_keys(1)

    outbound = account.create_outbound_session(peer.curve25519_key, peer.one_time_keys.values.first)
    _type, body = outbound.encrypt("hello")

    session, plaintext = peer.create_inbound_session(account.curve25519_key, body)

    expect(plaintext).to be == "hello"
    expect(session.session_id).to be == outbound.session_id
  end
end

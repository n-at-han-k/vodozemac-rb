# frozen_string_literal: true

# Released under the Apache License, Version 2.0.
# Copyright, 2026, by General Intelligence Systems.

require "vodozemac"

describe Vodozemac::Session do
  let(:pickle_key) {"0123456789abcdef0123456789abcdef"}

  # Two accounts with a session between them, which is the only way to get one.
  def pair
    alice = Vodozemac::Account.new
    bob = Vodozemac::Account.new
    bob.generate_one_time_keys(1)

    outbound = alice.create_outbound_session(bob.curve25519_key, bob.one_time_keys.values.first)

    [alice, bob, outbound]
  end

  it "encrypts a pre-key message until it has heard back" do
    _alice, _bob, outbound = self.pair
    type, body = outbound.encrypt("hello")

    expect(type).to be == 0
    expect(body).to be_a(String)
    expect(outbound.has_received_message).to be == false
  end

  it "reads a message back over the session it arrived on" do
    alice, bob, outbound = self.pair
    _type, body = outbound.encrypt("hello")

    inbound, _plaintext = bob.create_inbound_session(alice.curve25519_key, body)
    type, reply = inbound.encrypt("hello yourself")

    expect(inbound.has_received_message).to be == true
    expect(outbound.decrypt(type, reply)).to be == "hello yourself"
  end

  it "shares one ID between both halves" do
    alice, bob, outbound = self.pair
    _type, body = outbound.encrypt("hello")

    inbound, _plaintext = bob.create_inbound_session(alice.curve25519_key, body)

    expect(inbound.session_id).to be == outbound.session_id
  end

  it "survives a pickle" do
    _alice, _bob, outbound = self.pair

    restored = Vodozemac::Session.from_pickle(outbound.pickle(pickle_key), pickle_key)

    expect(restored.session_id).to be == outbound.session_id
  end

  it "refuses a message it cannot read" do
    _alice, _bob, outbound = self.pair

    expect{outbound.decrypt(1, "AAAA")}.to raise_exception(RuntimeError)
  end
end

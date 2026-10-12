# frozen_string_literal: true

# Released under the Apache License, Version 2.0.
# Copyright, 2026, by General Intelligence Systems.

require "vodozemac"

describe Vodozemac::InboundGroupSession do
  let(:pickle_key) {"0123456789abcdef0123456789abcdef"}

  # An outbound session and an inbound one which starts where it starts, built in that order.
  #
  # The order matters: a session key read after a message has been encrypted carries the ratchet as
  # it then stands, so an inbound session built from it cannot read what came before.
  def pair
    group = Vodozemac::GroupSession.new

    [group, Vodozemac::InboundGroupSession.new(group.session_key)]
  end

  it "shares the outbound session's ID" do
    group, inbound = self.pair

    expect(inbound.session_id).to be == group.session_id
  end

  it "reads a message, and says which index it was sent at" do
    group, inbound = self.pair

    plaintext, index = inbound.decrypt(group.encrypt("hello"))

    expect(plaintext).to be == "hello"
    expect(index).to be == 0
  end

  it "refuses a message from another session" do
    _group, inbound = self.pair
    other = Vodozemac::GroupSession.new

    expect{inbound.decrypt(other.encrypt("hello"))}.to raise_exception(RuntimeError)
  end

  it "knows the earliest index it holds" do
    _group, inbound = self.pair

    expect(inbound.first_known_index).to be == 0
  end

  it "exports a key at the index it starts from" do
    _group, inbound = self.pair

    expect(inbound.export_at(0)).to be_a(String)
  end

  # The ratchet runs forward, so an index it has not reached is one it can still get to.
  it "exports a key at an index it has not reached yet" do
    _group, inbound = self.pair

    expect(inbound.export_at(10)).to be_a(String)
  end

  # Backwards is the direction megolm cannot go, which is what makes history unreadable by design.
  it "exports nothing for an index it has already left behind" do
    _group, inbound = self.pair
    inbound.advance_to(5)

    expect(inbound.export_at(0)).to be == nil
  end

  it "imports an exported key" do
    group, inbound = self.pair

    imported = Vodozemac::InboundGroupSession.import(inbound.export_at_first_known_index)

    expect(imported.session_id).to be == group.session_id
    expect(imported.decrypt(group.encrypt("hello")).first).to be == "hello"
  end

  it "refuses a session key as an export, and an export as a session key" do
    group, inbound = self.pair
    exported = inbound.export_at_first_known_index

    expect{Vodozemac::InboundGroupSession.import(group.session_key)}.to raise_exception(RuntimeError)
    expect{Vodozemac::InboundGroupSession.new(exported)}.to raise_exception(RuntimeError)
  end

  it "recognises two copies of one session" do
    group, inbound = self.pair
    other = Vodozemac::InboundGroupSession.new(group.session_key)

    expect(inbound.connected(other)).to be == true
    expect(inbound.compare(other)).to be == :equal
  end

  it "recognises a session it has nothing to do with" do
    _group, inbound = self.pair
    other = Vodozemac::InboundGroupSession.new(Vodozemac::GroupSession.new.session_key)

    expect(inbound.connected(other)).to be == false
    expect(inbound.compare(other)).to be == :unconnected
  end

  it "says which copy holds more of the ratchet" do
    _group, inbound = self.pair
    behind = Vodozemac::InboundGroupSession.import(inbound.export_at(2))

    expect(inbound.compare(behind)).to be == :better
    expect(behind.compare(inbound)).to be == :worse
  end

  it "advances past the history it is not to read" do
    _group, inbound = self.pair

    expect(inbound.advance_to(2)).to be == true
    expect(inbound.first_known_index).to be == 2
  end

  it "does not advance backwards" do
    _group, inbound = self.pair
    inbound.advance_to(5)

    expect(inbound.advance_to(1)).to be == false
  end

  it "cannot read what it has advanced past" do
    group, inbound = self.pair
    ciphertext = group.encrypt("hello")
    inbound.advance_to(2)

    expect{inbound.decrypt(ciphertext)}.to raise_exception(RuntimeError)
  end

  it "survives a pickle" do
    _group, inbound = self.pair

    restored = Vodozemac::InboundGroupSession.from_pickle(inbound.pickle(pickle_key), pickle_key)

    expect(restored.session_id).to be == inbound.session_id
  end
end

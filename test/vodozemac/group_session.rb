# frozen_string_literal: true

# Released under the Apache License, Version 2.0.
# Copyright, 2026, by General Intelligence Systems.

require "vodozemac"

describe Vodozemac::GroupSession do
  let(:group) {Vodozemac::GroupSession.new}
  let(:pickle_key) {"0123456789abcdef0123456789abcdef"}

  it "starts at the first message index" do
    expect(group.message_index).to be == 0
  end

  it "has an ID and a key to share" do
    expect(group.session_id).to be_a(String)
    expect(group.session_key).to be_a(String)
  end

  it "moves the ratchet on with every message" do
    group.encrypt("one")
    group.encrypt("two")

    expect(group.message_index).to be == 2
  end

  it "encrypts to base64" do
    expect(group.encrypt("hello")).to be_a(String)
  end

  it "survives a pickle" do
    group.encrypt("one")

    restored = Vodozemac::GroupSession.from_pickle(group.pickle(pickle_key), pickle_key)

    expect(restored.session_id).to be == group.session_id
    expect(restored.message_index).to be == group.message_index
  end
end

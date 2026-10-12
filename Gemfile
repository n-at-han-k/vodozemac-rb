# frozen_string_literal: true

# Released under the Apache License, Version 2.0.
# Copyright, 2026, by General Intelligence Systems.

source "https://rubygems.org"

gemspec

group :test do
  gem "sus"
end

# The maintainer's half of gem_kit, which the published gem has no use for: one RubyGems command, `gem kit`, for bumping the version, writing and linting the changelog, listing the outstanding deprecations, releasing and tagging.
group :release do
  gem "gem_kit-release"
end

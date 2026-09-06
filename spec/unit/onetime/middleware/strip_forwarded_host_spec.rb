# spec/unit/onetime/middleware/strip_forwarded_host_spec.rb
#
# frozen_string_literal: true

require 'spec_helper'
require 'onetime/middleware/strip_forwarded_host'

# Unit tests for StripForwardedHost (finding G-01, defense in depth).
#
# The middleware's contract has two halves and both are security-relevant:
#
#   1. No forwarded AUTHORITY survives. `X-Forwarded-Host` and the RFC 7239
#      `Forwarded` header are deleted outright — no parsing, so no quoting
#      trick can smuggle a `host=` past the strip — and `Rack::Request#host`
#      can only ever resolve the `Host:` authority the edge received.
#
#   2. The scheme Rack resolved from `Forwarded` (under the process-wide
#      forwarded_priority otto 2.10 pins) survives in `rack.url_scheme`, the
#      key `Rack::Request#scheme` falls back to once no forwarded carrier is
#      present. A depth-mode `Forwarded`-only proxy keeps its TLS scheme;
#      the X-Forwarded-* family is untouched and resolves on its own.
RSpec.describe Onetime::Middleware::StripForwardedHost do
  subject(:middleware) { described_class.new(app) }

  let(:app) { ->(env) { @seen_env = env; [200, {}, ['ok']] } }

  def call_with(env)
    middleware.call(env)
    @seen_env
  end

  # Rack's forwarded_priority is process-global class state that otto 2.10
  # pins per process (spec_helper resets it after every example). Each
  # example sets the priority it is asserting against.
  around do |example|
    original = Rack::Request.forwarded_priority
    example.run
  ensure
    Rack::Request.forwarded_priority = original
  end

  describe 'X-Forwarded-Host' do
    it 'deletes the header unconditionally' do
      env = call_with('HTTP_X_FORWARDED_HOST' => 'evil.example.com', 'HTTP_HOST' => 'onetime.test')
      expect(env).not_to have_key('HTTP_X_FORWARDED_HOST')
      expect(env['HTTP_HOST']).to eq('onetime.test')
    end
  end

  describe 'RFC 7239 Forwarded' do
    it 'deletes the header unconditionally' do
      env = call_with(Rack::MockRequest.env_for('http://onetime.test/', 'HTTP_FORWARDED' => 'for=192.0.2.60;proto=https;host=evil.example.com'))
      expect(env).not_to have_key('HTTP_FORWARDED')
    end

    it 'deletes a header built to survive a quote-unaware host edit' do
      # A parser that disagrees with Rack's on quoting could keep this host=.
      # Whole-header delete has no parser to disagree with.
      Rack::Request.forwarded_priority = [:forwarded, :x_forwarded]

      env = call_with(Rack::MockRequest.env_for('http://onetime.test/', 'HTTP_FORWARDED' => 'for=a"b;host=evil.example.com'))
      aggregate_failures do
        expect(env).not_to have_key('HTTP_FORWARDED')
        expect(Rack::Request.new(env).host).to eq('onetime.test')
      end
    end

    it 'leaves the env untouched when no forwarded header is present' do
      env = call_with('HTTP_HOST' => 'onetime.test', 'rack.url_scheme' => 'http')
      aggregate_failures do
        expect(env).not_to have_key('HTTP_FORWARDED')
        expect(env['rack.url_scheme']).to eq('http')
      end
    end
  end

  describe 'post-strip Rack resolution' do
    let(:env) do
      Rack::MockRequest.env_for(
        'http://onetime.test/',
        'HTTP_X_FORWARDED_HOST' => 'evil.example.com',
        'HTTP_FORWARDED' => 'for=192.0.2.60;proto=https;host=evil.example.com',
      )
    end

    it 'resolves host from Host: regardless of forwarded_priority' do
      Rack::Request.forwarded_priority = [:forwarded, :x_forwarded]
      expect(Rack::Request.new(call_with(env)).host).to eq('onetime.test')
    end

    it 'carries the Forwarded proto into rack.url_scheme when the pinned family reads Forwarded (depth mode)' do
      Rack::Request.forwarded_priority = [:forwarded]

      request = Rack::Request.new(call_with(env))
      aggregate_failures do
        expect(request.env['rack.url_scheme']).to eq('https')
        expect(request.scheme).to eq('https')
      end
    end

    it 'does not honor the Forwarded proto when the pinned family is X-Forwarded-* (default)' do
      Rack::Request.forwarded_priority = [:x_forwarded]
      expect(Rack::Request.new(call_with(env)).scheme).to eq('http')
    end

    it 'still resolves scheme from the untouched X-Forwarded-Proto under the default family' do
      Rack::Request.forwarded_priority = [:x_forwarded]

      env['HTTP_X_FORWARDED_PROTO'] = 'https'
      expect(Rack::Request.new(call_with(env)).scheme).to eq('https')
    end

    it 'never downgrades a scheme AssumeHttps upgraded (Forwarded proto=http)' do
      # AssumeHttps mounts far above this middleware and sets BOTH env['HTTPS']
      # and rack.url_scheme. Rack::Request#scheme checks HTTPS='on' BEFORE any
      # forwarded carrier, so the pre-strip read this middleware writes back
      # resolves to https and the client-supplied proto=http cannot undo the
      # operator's assume_https policy.
      Rack::Request.forwarded_priority = [:forwarded]

      env['HTTP_FORWARDED']  = 'proto=http;host=evil.example.com'
      env['HTTPS']           = 'on'
      env['rack.url_scheme'] = 'https'

      request = Rack::Request.new(call_with(env))
      aggregate_failures do
        expect(request.env['rack.url_scheme']).to eq('https')
        expect(request).to be_ssl
      end
    end

    it 'does not upgrade a plain http request that carries only a Forwarded host' do
      Rack::Request.forwarded_priority = [:forwarded]

      env['HTTP_FORWARDED'] = 'host=evil.example.com'
      expect(Rack::Request.new(call_with(env)).scheme).to eq('http')
    end
  end
end

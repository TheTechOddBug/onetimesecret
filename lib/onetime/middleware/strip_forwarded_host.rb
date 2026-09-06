# lib/onetime/middleware/strip_forwarded_host.rb
#
# frozen_string_literal: true

module Onetime
  module Middleware
    # StripForwardedHost — remove client-settable forwarded-AUTHORITY signals
    # from the Rack env so `Rack::Request#host` can never carry a host the
    # client chose (finding G-01, defense in depth).
    #
    # ## Why this exists
    #
    # Rack 3.2's `Rack::Request#host` resolves through `forwarded_authority`
    # FIRST: it honors `X-Forwarded-Host` and RFC 7239 `Forwarded` from ANY
    # client, with no proxy-trust gate. Rodauth's stock `base_url` (and any
    # other code reading `request.host`) would therefore build an auth URL on
    # a host the client forged — reset-link poisoning, one click from account
    # takeover on the multi-tenant platform.
    #
    # The primary fix lives in Auth::PublicHost / the base_url override, which
    # allowlist the host to a registered tenant and otherwise fall back to the
    # CANONICAL host, never `request.host`. This middleware is the belt to that
    # brace: with the forwarded-host signals gone, even a direct
    # `request.host` read (a future consumer, a gem) resolves to the `Host:`
    # authority the edge actually received — never a client-supplied one —
    # regardless of the operator's proxy configuration.
    #
    # ## Relationship to otto 2.10
    #
    # otto 2.10 pins `Rack::Request.forwarded_priority` to the family chosen
    # in MiddlewareStack.ip_privacy_security_config ([:x_forwarded] unless
    # depth mode names `Forwarded`), and its IPPrivacyMiddleware deletes every
    # forwarded authority carrier from an untrusted peer once proxy trust is
    # configured. This middleware still runs unconditionally: otto strips
    # nothing while trust is unconfigured (the default deployment), and keeps
    # a trusted peer's carriers because it cannot tell a value the proxy set
    # from one the proxy passed through. Both headers are deleted here, so the
    # host authority that reaches every later reader is `Host:` alone.
    #
    # ## Whole-header delete, scheme handed to `rack.url_scheme`
    #
    # `Forwarded` multiplexes host with `proto`/`for`/`by`. An earlier version
    # of this middleware edited only the `host=` parameters out so a
    # `Forwarded`-only proxy kept its TLS scheme. That needs a second RFC 7239
    # parser, and a parser that disagrees with Rack's on quoting lets a
    # `host=` survive the edit (`for=a"b;host=evil` is enough). Deletion has
    # no such failure mode. The one thing Rack legitimately read from the
    # header — the scheme, under the pinned family — is resolved by Rack
    # itself BEFORE the delete and written to `rack.url_scheme`, the key
    # `Rack::Request#scheme` falls back to once no forwarded carrier is
    # present. No parsing happens here; Rack's answer before the strip is
    # Rack's answer after it. `X-Forwarded-Proto` and `X-Forwarded-SSL` are
    # not touched, so the X-Forwarded-* family continues to resolve on its
    # own; `for=` has already been consumed by otto's IP resolution, which
    # runs first.
    #
    # ## Ordering — AFTER DetectHost AND AdminNetworkIsolation, before
    # ## anything reads request.host
    #
    # Two upstream middlewares legitimately consume the raw headers, so both
    # must run first:
    #
    #   - Rack::DetectHost has its OWN trust logic: it honors a forwarded host
    #     ONLY from trusted infrastructure and publishes the result into
    #     env[Rack::DetectHost.result_field_name] (which DomainStrategy then
    #     classifies). That legitimate resolution — the whole custom-domain-
    #     behind-a-proxy topology — MUST keep working.
    #   - Onetime::Middleware::AdminNetworkIsolation's forwarded-host
    #     PROVENANCE rule (host_provenance_trusted?) keys on the PRESENCE of
    #     these headers: "no forwarded header present" is its rule (b) for
    #     accepting a detected host. Stripping before it destroys the evidence
    #     that a detected host was forwarded by an untrusted peer, and the
    #     admin gate would admit exactly the spoof it exists to deny.
    #
    # Nothing between DetectHost and here reads `Rack::Request#host` (the
    # middlewares in between read the resolved env keys, not the raw
    # authority), and the mounted apps run later still, so by the time any
    # `request.host` read happens the forwarded host is gone. DetectHost's
    # and the admin gate's logic are left entirely intact — this only deletes
    # what they have already used.
    class StripForwardedHost
      # Carries only an authority: deleted outright.
      X_FORWARDED_HOST = 'HTTP_X_FORWARDED_HOST'

      # RFC 7239 — multiplexes host with proto/for/by: deleted outright, the
      # scheme Rack resolved from it is carried in rack.url_scheme.
      FORWARDED = 'HTTP_FORWARDED'

      # Rack's fallback scheme key (Rack::RACK_URL_SCHEME).
      RACK_URL_SCHEME = 'rack.url_scheme'

      def initialize(app)
        @app = app
      end

      def call(env)
        env[RACK_URL_SCHEME] = Rack::Request.new(env).scheme if env.key?(FORWARDED)

        env.delete(X_FORWARDED_HOST)
        env.delete(FORWARDED)

        @app.call(env)
      end
    end
  end
end

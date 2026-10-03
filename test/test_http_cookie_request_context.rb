# frozen_string_literal: false
require File.expand_path('helper', File.dirname(__FILE__))
require 'tmpdir'
require 'stringio'

module TestHTTPCookieJar
  # Offline (no network) request-sequence tests for schemeful
  # SameSite selection and CHIPS partitioning driven by an explicit
  # HTTP::Cookie::RequestContext.
  class TestRequestContext < Test::Unit::TestCase
    TOP      = 'https://www.example.com'
    SIBLING  = 'https://cdn.example.com'
    OTHER    = 'https://www.other.test'
    TRACKER  = 'https://tracker.example'
    SAME     = 'https://ads.thirdparty.com'
    SAME_TOP = 'https://www.thirdparty.com'

    def setup
      @jar = HTTP::CookieJar.new(:gc_threshold => 1500)
    end

    # Adds a cookie set by the tracker while the top-level document
    # is +top+; this is a cross-site response carrying Set-Cookie.
    def set_from_tracker(set_cookie, top = TOP, target = TRACKER)
      context = HTTP::Cookie::RequestContext.new(target,
        :top_level_site       => top,
        :initiator_site       => top,
        :top_level_navigation => false,
        :method               => 'GET')
      @jar.parse(set_cookie, target, :context => context)
    end

    # Returns the names of cookies that would be sent to the tracker
    # for the given request context.
    def send_names(context, uri = TRACKER)
      @jar.cookies(uri, :context => context).map(&:name).sort
    end

    def subresource_context(top: TOP, initiator: TOP, method: 'GET')
      HTTP::Cookie::RequestContext.new(TRACKER,
        :top_level_site       => top,
        :initiator_site       => initiator,
        :top_level_navigation => false,
        :method               => method)
    end

    def navigation_context(top: OTHER, method: 'GET', redirect_chain: nil)
      HTTP::Cookie::RequestContext.new(TRACKER,
        :top_level_site       => top,
        :initiator_site       => top,
        :top_level_navigation => true,
        :method               => method,
        :redirect_chain       => redirect_chain)
    end

    def seed_same_site_variants(target = TRACKER)
      set_from_tracker('strict=1; Secure; SameSite=Strict; Path=/', TOP, target)
      set_from_tracker('lax=1;    Secure; SameSite=Lax;    Path=/', TOP, target)
      set_from_tracker('none=1;   Secure; SameSite=None;   Path=/', TOP, target)
      set_from_tracker('plain=1;  Secure;                  Path=/', TOP, target)
    end

    # --- Offline request sequence: cross-site POST -----------------

    def test_cross_site_post_sends_only_none
      seed_same_site_variants

      # 1. The top document at other.test embeds the tracker via a
      #    cross-site POST subresource: only SameSite=None and the
      #    attribute-less cookie go out.
      names = send_names(subresource_context(:top => OTHER,
                                             :method => 'POST'))
      assert_equal %w[none plain], names

      # 2. A cross-site GET subresource (e.g. an <img>) is not a
      #    top-level navigation, so Lax cookies are still withheld.
      names = send_names(subresource_context(:top => OTHER,
                                             :method => 'GET'))
      assert_equal %w[none plain], names
    end

    # --- Offline request sequence: same-site subresource -----------

    def test_same_site_subresource_sends_everything
      seed_same_site_variants(SAME)

      # A subresource request issued by a page whose site matches
      # the target site, even from a different subdomain and over a
      # POST, carries all cookies.
      context = HTTP::Cookie::RequestContext.new(SAME,
        :top_level_site       => SAME_TOP,
        :initiator_site       => 'https://img.thirdparty.com',
        :top_level_navigation => false,
        :method               => 'POST')
      names = send_names(context, SAME)
      assert_equal %w[lax none plain strict], names
    end

    def test_schemeful_site_distinguishes_scheme
      seed_same_site_variants

      # http:// is a different schemeful site from https://.
      names = send_names(subresource_context(:top => 'http://www.example.com',
                                             :method => 'POST'))
      assert_equal %w[none plain], names
    end

    # --- Offline request sequence: cross-site top-level navigation -

    def test_cross_site_top_level_get_navigation_is_lax
      seed_same_site_variants

      # Following a link into the tracker (top-level GET): Strict is
      # withheld, Lax/None/plain are sent.
      names = send_names(navigation_context)
      assert_equal %w[lax none plain], names
    end

    def test_cross_site_top_level_post_is_none
      seed_same_site_variants

      names = send_names(navigation_context(:method => 'POST'))
      assert_equal %w[none plain], names
    end

    # --- Offline request sequence: cross-site redirect chain -------

    def test_cross_site_post_redirect_to_get_still_withholds_lax
      seed_same_site_variants

      # A form POST at other.test returns 302 to the tracker, which
      # is fetched with a top-level GET.  Because the navigation
      # started as an unsafe cross-site request, Lax+POST keeps the
      # Lax cookie withheld; only None/plain are sent.
      context = navigation_context(
        :method => 'GET',
        :redirect_chain => [
          { :uri => OTHER, :method => 'POST' },
        ])
      assert_equal %w[none plain], send_names(context)
    end

    def test_cross_site_get_redirect_chain_sends_lax
      seed_same_site_variants

      # A plain cross-site top-level GET redirect keeps the whole
      # chain safe, so Lax is sent while Strict is not.
      context = navigation_context(
        :method => 'GET',
        :redirect_chain => [
          { :uri => OTHER, :method => 'GET' },
        ])
      assert_equal %w[lax none plain], send_names(context)
    end

    def test_same_site_redirect_chain_sends_strict
      seed_same_site_variants(SAME)

      # Start on the same site (a sibling host), even via a POST;
      # every hop stays same-site, so Strict is sent.
      context = HTTP::Cookie::RequestContext.new(SAME,
        :top_level_site       => SAME_TOP,
        :initiator_site       => 'https://m.thirdparty.com',
        :top_level_navigation => true,
        :method               => 'GET',
        :redirect_chain       => [
          { :uri => 'https://m.thirdparty.com', :method => 'POST' },
        ])
      assert_equal %w[lax none plain strict], send_names(context, SAME)
    end

    def test_cross_site_hop_followed_by_same_site_hop_withholds_strict
      seed_same_site_variants

      # other.test 302 -> cdn.example.com 302 -> tracker: the chain
      # crosses a site boundary, so Strict is withheld, but the rest
      # of the chain is safe GET navigation, which admits Lax.
      context = navigation_context(
        :method => 'GET',
        :redirect_chain => [
          { :uri => OTHER,   :method => 'GET' },
          { :uri => SIBLING, :method => 'GET' },
        ])
      assert_equal %w[lax none plain], send_names(context)
    end

    # --- Partitioned cookies (CHIPS) --------------------------------

    def partitioned_set_cookie
      'pa=1; Secure; SameSite=None; Path=/; Partitioned'
    end

    def set_partitioned(top)
      context = HTTP::Cookie::RequestContext.new(TRACKER,
        :top_level_site       => top,
        :initiator_site       => top,
        :top_level_navigation => false,
        :method               => 'GET')
      @jar.parse(partitioned_set_cookie, TRACKER, :context => context)
    end

    def test_same_third_party_name_coexists_in_two_partitions
      set_partitioned(TOP)
      set_partitioned(OTHER)

      assert_equal 2, @jar.cookies.size
      partitions = @jar.cookies.map(&:partition_key).sort
      expected = [
        HTTP::Cookie::RequestContext.site_of(OTHER),
        HTTP::Cookie::RequestContext.site_of(TOP),
      ].sort
      assert_equal expected, partitions

      # Each partitioned cookie is only sent inside its partition,
      # regardless of the request method.
      assert_equal %w[pa],
        send_names(subresource_context(:top => TOP, :method => 'POST'))
      assert_equal %w[pa],
        send_names(subresource_context(:top => OTHER, :method => 'POST'))

      # A third top-level site with the same embedded tracker gets
      # nothing.
      third = 'https://shop.example.org'
      assert_equal [],
        send_names(subresource_context(:top => third, :method => 'POST'))
    end

    def test_partitioned_cookie_is_not_sent_without_partition_match
      set_partitioned(TOP)

      # Legacy selection (no context) yields the raw cookie,
      # including its partition metadata.
      assert_equal %w[pa], @jar.cookies(TRACKER).map(&:name)

      # Explicit context for a different partition withholds it.
      assert_equal [], send_names(subresource_context(:top => OTHER))
    end

    def test_delete_keeps_partitions_distinct
      set_partitioned(TOP)
      set_partitioned(OTHER)

      context_top = subresource_context(:top => TOP)
      context_other = subresource_context(:top => OTHER)

      cookie = HTTP::Cookie.new('pa', :domain => 'tracker.example',
                                :path => '/')
      # Deleting without a partition touches neither partitioned
      # cookie.
      @jar.delete(cookie)
      assert_equal 2, @jar.cookies.size

      # Deleting with the TOP partition removes only that copy.
      @jar.delete(cookie, context_top)
      assert_equal 1, @jar.cookies.size
      assert_equal [], send_names(context_top)
      assert_equal %w[pa], send_names(context_other)
    end

    def test_yaml_round_trip_preserves_partitions
      set_partitioned(TOP)
      set_partitioned(OTHER)

      io = StringIO.new
      @jar.save(io, :format => :yaml, :session => true)
      io.rewind

      restored = HTTP::CookieJar.new
      restored.load(io, :format => :yaml)
      assert_equal 2, restored.cookies.size

      assert_equal %w[pa], restored.cookies(TRACKER,
        :context => subresource_context(:top => TOP,
                                        :method => 'POST')).map(&:name)
      assert_equal %w[pa], restored.cookies(TRACKER,
        :context => subresource_context(:top => OTHER,
                                        :method => 'POST')).map(&:name)
    end

    def test_cookiestxt_skips_partitioned_cookies
      set_partitioned(TOP)

      io = StringIO.new
      @jar.save(io, :format => :cookiestxt, :session => true)
      assert_not_match(/\bpa\t/, io.string)
    end

    # --- Acceptance rules in the new mode --------------------------

    def test_same_site_none_requires_secure_with_context
      context = subresource_context
      assert_raise(ArgumentError) {
        @jar.parse('bad=1; SameSite=None; Path=/', 'http://tracker.example/',
                   :context => context)
      }
      assert_equal 0, @jar.cookies.size
    end

    def test_partitioned_requires_secure_and_none
      context = subresource_context
      assert_raise(ArgumentError) {
        @jar.parse('bad=1; Secure; SameSite=Lax; Path=/; Partitioned',
                   TRACKER, :context => context)
      }
      assert_equal 0, @jar.cookies.size
    end

    # --- Legacy mode (no context) keeps the old behaviour -----------

    def test_legacy_mode_ignores_same_site
      seed_same_site_variants

      # Without a context every non-expired valid cookie is selected.
      assert_equal %w[lax none plain strict],
        @jar.cookies(TRACKER).map(&:name).sort
    end

    def test_legacy_add_of_partitioned_cookie_is_rejected
      cookie = HTTP::Cookie.new('pa', '1',
        :domain => 'tracker.example', :path => '/',
        :secure => true, :same_site => 'None', :partitioned => true)
      assert_raise(ArgumentError) { @jar.add(cookie) }
    end

    def test_samesite_attribute_parsing_and_serialization
      cookie = HTTP::Cookie.parse(
        'a=1; SameSite=lax', TRACKER).first
      assert_equal HTTP::Cookie::SAME_SITE_LAX, cookie.same_site
      assert_match(/SameSite=Lax/, cookie.set_cookie_value)

      partitioned = @jar.tap { |jar|
        set_from_tracker('z=1; Secure; SameSite=None; Path=/; Partitioned')
      }.cookies(TRACKER).first
      assert partitioned.partitioned?
      assert_match(/Partitioned/, partitioned.set_cookie_value)
    end

    def test_site_of_is_schemeful
      assert_equal 'https://example.com',
        HTTP::Cookie::RequestContext.site_of('https://www.example.com/path')
      assert_equal 'http://example.com',
        HTTP::Cookie::RequestContext.site_of('http://example.com')
      assert_equal 'https://localhost',
        HTTP::Cookie::RequestContext.site_of('https://localhost:8443/x')
    end
  end
end

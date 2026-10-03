# frozen_string_literal: true
require File.expand_path('helper', File.dirname(__FILE__))
require 'stringio'

# Tests for the explicit request context (top-level site, initiator
# site, top-level-navigation flag, HTTP method, redirect chain), the
# schemeful SameSite selection rules and the Partitioned (CHIPS)
# top-level-site partitioning.
#
# These tests drive the jar with an offline sequence of requests; no
# network is used.
class TestHTTPCookieJarContext < Test::Unit::TestCase
  SHOP = 'https://shop.example'.freeze
  NEWS = 'https://news.example'.freeze
  TRACKER_HTTPS = 'https://tracker.example/img'.freeze
  TRACKER_HTTP = 'http://tracker.example/img'.freeze

  def setup
    @jar = HTTP::CookieJar.new
  end

  def context(uri, top_level_site:, method: 'GET', top_level_navigation: false,
              initiator_site: nil, redirect_chain: nil)
    HTTP::CookieJar::RequestContext.new(
      uri,
      top_level_site: top_level_site,
      initiator_site: initiator_site,
      top_level_navigation: top_level_navigation,
      method: method,
      redirect_chain: redirect_chain
    )
  end

  def header(uri, context = nil)
    cookies =
      if context
        @jar.cookies(uri, context: context)
      else
        @jar.cookies(uri)
      end
    HTTP::Cookie.cookie_value(cookies)
  end

  # Seeds the third-party tracker host with one cookie of each flavor.
  def seed_tracker!
    @jar.parse('strict=s; SameSite=Strict', TRACKER_HTTP)
    @jar.parse('lax=l; SameSite=Lax', TRACKER_HTTP)
    @jar.parse('plain=p', TRACKER_HTTP)
    @jar.parse('none=n; Secure; SameSite=None', TRACKER_HTTPS)
  end

  # ------------------------------------------------------------------
  # Site / RequestContext basics
  # ------------------------------------------------------------------

  def test_site_is_schemeful_etld_plus_one
    site = HTTP::CookieJar::Site.from('https://www.example.co.uk/path')
    assert_equal 'https://example.co.uk', site.to_s
    assert_equal site, HTTP::CookieJar::Site.from('https://other.example.co.uk/')
  end

  def test_site_distinguishes_scheme
    http_site = HTTP::CookieJar::Site.from('http://example.com')
    https_site = HTTP::CookieJar::Site.from('https://example.com')
    assert_not_equal http_site, https_site
  end

  def test_site_uses_full_host_for_ip_address
    site = HTTP::CookieJar::Site.from('https://192.0.2.10/x')
    assert_equal 'https://192.0.2.10', site.to_s
  end

  def test_site_rejects_non_http_uri
    assert_raise(ArgumentError) {
      HTTP::CookieJar::Site.from('ftp://example.com')
    }
  end

  def test_context_coercion_from_hash
    rc = HTTP::CookieJar::RequestContext.associate(
      request_uri: TRACKER_HTTP,
      top_level_site: 'http://shop.example',
      method: 'post'
    )
    assert_instance_of HTTP::CookieJar::RequestContext, rc
    assert_equal 'POST', rc.method
    assert_equal 'http://shop.example', rc.top_level_site.to_s
    assert rc.cross_site?
  end

  def test_same_site_requires_whole_redirect_chain
    rc = context(TRACKER_HTTP, top_level_site: 'http://tracker.example',
                 redirect_chain: ['http://tracker.example/login'])
    assert rc.same_site?

    rc = context(TRACKER_HTTP, top_level_site: 'http://tracker.example',
                 redirect_chain: ['http://login.example/start'])
    assert rc.cross_site?
  end

  def test_context_without_top_level_site_is_cross_site
    rc = HTTP::CookieJar::RequestContext.new(TRACKER_HTTP)
    assert rc.cross_site?
    assert !rc.same_site?
  end

  # ------------------------------------------------------------------
  # Offline request sequence
  # ------------------------------------------------------------------

  def test_offline_request_sequence
    seed_tracker!

    # 1) A cross-site POST form submission.  Only cookies without a
    #    SameSite attribute are sent; Strict, Lax and None (this is
    #    plain HTTP) are withheld.
    post = context(TRACKER_HTTP, top_level_site: 'http://shop.example',
                   method: 'POST')
    assert_equal 'plain=p', header(TRACKER_HTTP, post)

    # The same POST over a secure connection also carries SameSite=None.
    post_secure = context(TRACKER_HTTPS, top_level_site: SHOP, method: 'POST')
    assert_equal %w[none=n plain=p],
                 header(TRACKER_HTTPS, post_secure).split('; ').sort

    # 2) A same-site subresource, even with an unsafe method, sends
    #    everything valid for the URL.
    same_site = context(TRACKER_HTTP, top_level_site: 'http://tracker.example',
                        method: 'POST', initiator_site: 'http://tracker.example')
    assert_equal %w[lax=l plain=p strict=s],
                 header(TRACKER_HTTP, same_site).split('; ').sort

    # 3a) A top-level cross-site GET navigation is "Lax": Lax and
    #     unmarked cookies go out, Strict does not.
    nav_get = context(TRACKER_HTTP, top_level_site: 'http://shop.example',
                      top_level_navigation: true, method: 'GET')
    assert_equal %w[lax=l plain=p],
                 header(TRACKER_HTTP, nav_get).split('; ').sort

    # 3b) A top-level cross-site POST is not a safe navigation.
    nav_post = context(TRACKER_HTTP, top_level_site: 'http://shop.example',
                       top_level_navigation: true, method: 'POST')
    assert_equal 'plain=p', header(TRACKER_HTTP, nav_post)
  end

  def test_cross_site_redirect_then_top_level_get_sends_lax
    seed_tracker!

    # The user follows a link at shop.example that 302-redirects to
    # tracker.example.  The eventual request is a safe top-level
    # navigation, so SameSite=Lax is allowed.
    rc = context(TRACKER_HTTP, top_level_site: 'http://shop.example',
                 top_level_navigation: true, method: 'GET',
                 redirect_chain: ['http://shop.example/out'])
    assert_equal %w[lax=l plain=p],
                 header(TRACKER_HTTP, rc).split('; ').sort
  end

  def test_redirect_off_site_mid_chain_breaks_same_site_strict
    seed_tracker!

    # Navigation that leaves the top-level site through the redirect
    # chain is cross-site for the purpose of SameSite=Strict.
    rc = context(TRACKER_HTTP, top_level_site: 'http://tracker.example',
                 top_level_navigation: true, method: 'GET',
                 redirect_chain: ['http://tracker.example/start',
                                  'http://login.example/bounce'])
    assert_equal %w[lax=l plain=p],
                 header(TRACKER_HTTP, rc).split('; ').sort
  end

  def test_legacy_behavior_without_context
    seed_tracker!
    # No context: every cookie valid for the URL is returned, just
    # like before the context was introduced.
    assert_equal %w[lax=l plain=p strict=s],
                 header(TRACKER_HTTP).split('; ').sort
    assert_equal %w[lax=l none=n plain=p strict=s],
                 header(TRACKER_HTTPS).split('; ').sort
  end

  # ------------------------------------------------------------------
  # SameSite attribute handling
  # ------------------------------------------------------------------

  def test_samesite_none_requires_secure
    @jar.parse('a=1; SameSite=None', TRACKER_HTTPS)
    assert @jar.empty?

    added = @jar.parse('a=1; Secure; SameSite=None', TRACKER_HTTPS)
    assert_equal 1, added.size
    assert_equal :none, added.first.same_site
    assert added.first.secure?
  end

  def test_unknown_samesite_value_ignored
    added = @jar.parse('a=1; SameSite=Banana', TRACKER_HTTP)
    assert_equal 0, added.size
  end

  def test_samesite_setter_normalizes_values
    cookie = HTTP::Cookie.new('a', '1', origin: TRACKER_HTTP)
    cookie.same_site = 'Lax'
    assert_equal :lax, cookie.same_site
    cookie.same_site = :strict
    assert_equal :strict, cookie.same_site
    assert_raise(ArgumentError) { cookie.same_site = 'banana' }
  end

  def test_set_cookie_value_includes_samesite_and_partitioned
    cookie = HTTP::Cookie.new('a', '1', origin: TRACKER_HTTPS,
                              secure: true, same_site: :none,
                              partitioned: true)
    assert_match(/; SameSite=None\b/, cookie.set_cookie_value)
    assert_match(/; Secure\b/, cookie.set_cookie_value)
    assert_match(/; Partitioned\b/, cookie.set_cookie_value)
  end

  def test_schemeful_difference_blocks_lax_in_subresource
    @jar.parse('lax=l; SameSite=Lax', 'https://tracker.example/img')
    # Same registrable domain but a different scheme is cross-site.
    rc = context('https://tracker.example/img',
                 top_level_site: 'http://tracker.example',
                 method: 'GET')
    assert_equal '', header('https://tracker.example/img', rc)
  end

  # ------------------------------------------------------------------
  # Partitioned cookies (CHIPS)
  # ------------------------------------------------------------------

  def seed_partitioned!
    @jar.parse('sid=shop; Max-Age=100; Secure; SameSite=None; Partitioned',
               TRACKER_HTTPS, top_level_site: SHOP)
    @jar.parse('sid=news; Max-Age=100; Secure; SameSite=None; Partitioned',
               TRACKER_HTTPS, top_level_site: NEWS)
    @jar.parse('sid=plain; Max-Age=100; Secure; SameSite=None', TRACKER_HTTPS)
  end

  def test_partitioned_cookies_coexist_per_top_level_site
    seed_partitioned!
    all = @jar.cookies.select { |c| c.name == 'sid' }.sort_by(&:value)
    assert_equal %w[news plain shop], all.map(&:value)
    keys = all.map(&:partition_key)
    assert_include keys, SHOP
    assert_include keys, NEWS
    assert_include keys, nil
  end

  def test_partitioned_cookie_sent_only_in_its_partition
    seed_partitioned!

    shop = context(TRACKER_HTTPS, top_level_site: SHOP)
    assert_equal %w[sid=plain sid=shop],
                 header(TRACKER_HTTPS, shop).split('; ').sort

    news = context(TRACKER_HTTPS, top_level_site: NEWS)
    assert_equal %w[sid=news sid=plain],
                 header(TRACKER_HTTPS, news).split('; ').sort

    other = context(TRACKER_HTTPS, top_level_site: 'https://blog.example')
    assert_equal %w[sid=plain],
                 header(TRACKER_HTTPS, other).split('; ').sort
  end

  def test_partitioned_cookie_not_sent_for_http
    seed_partitioned!
    rc = context('http://tracker.example/img', top_level_site: 'http://shop.example')
    # Partitioned cookie is Secure and SameSite=None: never over HTTP.
    assert_equal '', header('http://tracker.example/img', rc)
  end

  def test_delete_keeps_partitions_distinct
    seed_partitioned!

    target = @jar.cookies.find { |c|
      c.name == 'sid' && c.partition_key == SHOP
    }
    @jar.delete(target)

    remaining = @jar.cookies.select { |c| c.name == 'sid' }.map(&:value).sort
    assert_equal %w[news plain], remaining
  end

  def test_delete_without_partition_key_does_not_remove_partitioned
    seed_partitioned!

    # A cookie descriptor without a partition key addresses only the
    # unpartitioned cookie.
    @jar.delete(HTTP::Cookie.new('sid', 'plain',
                                 origin: TRACKER_HTTPS,
                                 secure: true,
                                 same_site: :none,
                                 max_age: 100))
    remaining = @jar.cookies.select { |c| c.name == 'sid' }.map(&:value).sort
    assert_equal %w[news shop], remaining
  end

  def test_yaml_serialization_preserves_partitions
    seed_partitioned!

    io = StringIO.new
    @jar.save(io)
    io.rewind

    restored = HTTP::CookieJar.new
    restored.load(io)

    shop = context(TRACKER_HTTPS, top_level_site: SHOP)
    assert_equal %w[sid=plain sid=shop],
                 header_from(restored, TRACKER_HTTPS, shop).split('; ').sort

    news = context(TRACKER_HTTPS, top_level_site: NEWS)
    assert_equal %w[sid=news sid=plain],
                 header_from(restored, TRACKER_HTTPS, news).split('; ').sort
  end

  def header_from(jar, uri, context)
    HTTP::Cookie.cookie_value(jar.cookies(uri, context: context))
  end
end

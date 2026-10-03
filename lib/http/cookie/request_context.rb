# frozen_string_literal: true
require 'uri'
require 'domain_name'
require 'http/cookie/uri_parser'

class HTTP::Cookie
  # Represents the request context used for schemeful SameSite
  # filtering and cookie partitioning (CHIPS).
  #
  # A context is built for every outbound HTTP request and carries:
  #
  # * top_level_site: the schemeful site of the top-level document
  #    (the "site for cookies"), e.g. "https://example.com"
  # * initiator_site: the schemeful site of the frame/resource that
  #    initiated the request, e.g. "https://cdn.example.com"
  # * method: the HTTP method of the request
  # * top_level_navigation: whether the request is a top-level
  #    navigation
  # * redirect_chain: the requests that preceded this one while
  #    following redirects, given as URI/method pairs
  #
  # Site strings are "schemeful" (RFC 6265bis 5.2, Chrome's
  # "schemeful Same-Site"): the scheme is part of the comparison, so
  # http://example.com and https://example.com are cross-site.
  class RequestContext
    # Safe methods per RFC 9110; only safe requests may carry
    # SameSite=Lax cookies on a cross-site top-level navigation.
    SAFE_METHODS = %w[GET HEAD OPTIONS TRACE].freeze

    # Computes the schemeful site of a URI/URL.  Returns a string of
    # the form "https://example.com" or nil for a URI with no host.
    def self.site_of(uri)
      return nil if uri.nil?
      uri = HTTP::Cookie::URIParser.parse(uri) unless URI::Generic === uri
      host = uri.host or return nil
      domain = DomainName.new(host)
      registrable = domain.domain || domain.hostname
      "#{uri.scheme}://#{registrable}"
    end

    # call-seq:
    #   RequestContext.new(uri, **options)
    #
    # Generates a request context for the given request URI.  Options:
    #
    # :top_level_site
    # : Schemeful site of the top-level document.  Defaults to the
    #   site of +uri+ (a top-level request).
    #
    # :initiator_site
    # : Schemeful site of the request initiator.  Defaults to the
    #   top-level site.
    #
    # :method
    # : HTTP method of the request. (default: "GET")
    #
    # :top_level_navigation
    # : Whether this is a top-level navigation. (default: true)
    #
    # :redirect_chain
    # : Array of earlier requests in a redirect chain.  Each element
    #   is a URI/URL string, a URI object, or a
    #   <tt>{:uri=>uri, :method=>method}</tt> pair; the method
    #   defaults to the preceding request method or "GET".  The chain
    #   is ordered from the original request to the most recent
    #   redirect.
    def initialize(uri,
                   top_level_site: nil,
                   initiator_site: nil,
                   method: 'GET',
                   top_level_navigation: true,
                   redirect_chain: nil)
      @uri = HTTP::Cookie::URIParser.parse(uri)
      @top_level_site = normalize_site(top_level_site) ||
        self.class.site_of(@uri)
      @initiator_site = normalize_site(initiator_site) || @top_level_site
      @method = method.to_s.upcase
      @top_level_navigation = top_level_navigation ? true : false
      @redirect_chain = build_redirect_chain(redirect_chain)
    end

    # The request URI.
    attr_reader :uri

    # The schemeful top-level site (site for cookies).
    attr_reader :top_level_site

    # The schemeful site of the request initiator.
    attr_reader :initiator_site

    # The HTTP method string of the request, upper-cased.
    attr_reader :method

    # Whether the request is a top-level navigation.
    def top_level_navigation?
      @top_level_navigation
    end

    # The redirect chain as an array of [URI, method] pairs, oldest
    # first.
    attr_reader :redirect_chain

    # Tests whether the request method (or that of any redirect hop)
    # is a "safe" method per RFC 9110.
    def safe_method?
      SAFE_METHODS.include?(@method)
    end

    # Tests whether the request method and every method used along
    # the redirect chain are safe.
    def all_methods_safe?
      return false unless safe_method?
      redirect_chain.each { |_, request_method|
        return false unless SAFE_METHODS.include?(request_method)
      }
      true
    end

    # Returns the SameSite allowance of a request:
    #
    # :strict:: the request looks same-site all the way; cookies with
    #           SameSite=Strict, Lax or None may be sent
    # :lax::    a cross-site (possibly redirected) top-level
    #           navigation with only safe methods; SameSite=Lax and
    #           None cookies may be sent
    # :none::   any other cross-site request; only SameSite=None
    #           cookies may be sent
    #
    # The redirect handling follows the "lax+POST" model of the
    # storage access policy.  A request is considered same-site only
    # when the target site and every URI in the redirect chain are
    # same-site with the initiator/top-level site.  Once the chain is
    # cross-site, Strict cookies are withheld, and Lax cookies are
    # only sent when the whole chain (including the current request)
    # uses safe methods and the current request is a top-level
    # navigation.
    def send_mode
      target_site = self.class.site_of(@uri)
      chain_sites = redirect_chain.map { |hop_uri, _|
        self.class.site_of(hop_uri)
      }

      same_site = target_site == @top_level_site &&
        if redirect_chain.empty?
          true
        else
          chain_sites.all? { |site| site == @initiator_site }
        end

      if same_site
        :strict
      elsif @top_level_navigation && all_methods_safe?
        :lax
      else
        :none
      end
    end

    # Tests whether a cookie's SameSite attribute permits it to be
    # sent in this request context.  Partitioned cookies are handled
    # separately; see #matches_partition?.
    def allows_same_site?(cookie)
      case cookie.same_site
      when HTTP::Cookie::SAME_SITE_STRICT
        send_mode == :strict
      when HTTP::Cookie::SAME_SITE_LAX
        send_mode != :none
      when HTTP::Cookie::SAME_SITE_NONE, nil
        true
      else
        false
      end
    end

    # Tests whether a (partitioned) cookie belongs to this context's
    # top-level site partition.
    def matches_partition?(cookie)
      cookie.partition_key == @top_level_site
    end

    private

    def normalize_site(site)
      case site
      when nil
        nil
      when String, URI::Generic
        self.class.site_of(site)
      else
        raise TypeError, "#{site.class} is not a site or URI"
      end
    end

    def build_redirect_chain(chain)
      return [] if chain.nil?
      previous_method = @method
      chain.map { |hop|
        case hop
        when Hash
          hop_uri = hop.fetch(:uri) { hop.fetch('uri') }
          hop_method = hop[:method] || hop['method'] || previous_method
        else
          hop_uri = hop
          hop_method = previous_method
        end
        hop_uri = HTTP::Cookie::URIParser.parse(hop_uri)
        hop_method = hop_method.to_s.upcase
        previous_method = hop_method
        [hop_uri, hop_method]
      }
    end
  end
end

# frozen_string_literal: true

class HTTP::CookieJar
  # Represents an HTTP *site* as defined for schemeful SameSite:
  # the combination of the URI scheme and the registrable domain
  # (eTLD+1).  For an IP address or a host that has no registrable
  # domain, the scheme and the whole hostname are used.
  #
  # Two URIs are same-site if their sites are equal; differing schemes
  # (e.g. http vs https) make them cross-site, hence "schemeful".
  class Site
    # @return [String] the downcased URI scheme ("http" or "https")
    attr_reader :scheme

    # @return [String] the downcased registrable domain, or the host
    attr_reader :host

    def initialize(scheme, host)
      @scheme = scheme.downcase
      @host = host.downcase
    end

    # Builds a Site from a URI/URL string or URI object.  A Site is
    # returned as-is.
    def self.from(value)
      case value
      when self
        value
      else
        uri = HTTP::Cookie::URIParser.parse(value)
        unless URI::HTTP === uri && uri.host
          raise ArgumentError, "not an HTTP URI: #{value.inspect}"
        end
        domain_name = DomainName.new(uri.host)
        new(uri.scheme, domain_name.domain || domain_name.hostname)
      end
    end

    # @return [String] the site in the "scheme://eTLD+1" form
    def to_s
      "#{@scheme}://#{@host}"
    end

    def inspect
      "#<#{self.class} #{self}>"
    end

    def ==(other)
      case other
      when self.class
        scheme == other.scheme && host == other.host
      else
        other_site =
          begin
            self.class.from(other)
          rescue ArgumentError, TypeError
            nil
          end
        other_site ? (scheme == other_site.scheme && host == other_site.host) : false
      end
    end
    alias eql? ==

    def hash
      [scheme, host].hash
    end
  end

  # Describes the request for which cookies are to be selected.  It is
  # passed to HTTP::CookieJar#cookies, HTTP::CookieJar#each and friends
  # via the `:context` option so that the jar can apply the schemeful
  # SameSite rules and the top-level-site partitioning of Partitioned
  # (CHIPS) cookies.
  #
  #   context = HTTP::CookieJar::RequestContext.new(
  #     "https://widget.example/frame",
  #     top_level_site: "https://shop.example",
  #     method: "POST"
  #   )
  #   jar.cookies("https://widget.example/frame", context: context)
  class RequestContext
    # HTTP methods that are considered "safe" for SameSite=Lax
    # top-level navigations.
    SAFE_METHODS = %w[GET HEAD].freeze

    # @return [URI] the destination URI of the request
    attr_reader :request_uri

    # @return [Site, nil] the site of the top-level page
    attr_reader :top_level_site

    # @return [Site, nil] the site of the document that initiated the request
    attr_reader :initiator_site

    # @return [Array<String,URI>] the URIs followed to reach {#request_uri}
    attr_reader :redirect_chain

    # @param uri [String, URI] the request destination URI
    # @param top_level_site [String, URI, Site, nil] site of the top-level page
    # @param initiator_site [String, URI, Site, nil] site of the initiator
    # @param top_level_navigation [Boolean] whether this is a top-level navigation
    # @param method [String] the HTTP method (default "GET")
    # @param redirect_chain [Array<String, URI>] URIs redirected through
    def initialize(uri = nil, top_level_site: nil, initiator_site: nil,
                   top_level_navigation: false, method: 'GET',
                   redirect_chain: nil, request_uri: nil)
      uri ||= request_uri
      if uri.nil?
        raise ArgumentError, "request URI is required"
      end
      @request_uri = HTTP::Cookie::URIParser.parse(uri)
      unless URI::HTTP === @request_uri && @request_uri.host
        raise ArgumentError, "not an HTTP URI: #{uri.inspect}"
      end
      @top_level_site = top_level_site && Site.from(top_level_site)
      @initiator_site = initiator_site && Site.from(initiator_site)
      @top_level_navigation = !!top_level_navigation
      @method = String(method).upcase
      @redirect_chain = redirect_chain ? Array(redirect_chain) : []
    end

    # Coerces a value into a RequestContext.
    #
    # * a RequestContext is returned as-is,
    # * a Hash is treated as keyword arguments,
    # * a URI/URL string builds a bare context,
    # * nil returns nil.
    def self.associate(value)
      case value
      when nil
        nil
      when self
        value
      when Hash
        kwargs = {}
        value.each_pair { |key, val| kwargs[key.to_sym] = val }
        new(**kwargs)
      else
        new(value)
      end
    end

    # @return [Boolean] whether this is a top-level navigation request
    def top_level_navigation?
      @top_level_navigation
    end

    # @return [String] the uppercased HTTP method
    attr_reader :method

    # @return [Boolean] whether the method is a safe navigation method
    def safe_method?
      SAFE_METHODS.include?(@method)
    end

    # @return [Site] the site of the request destination
    def request_site
      @request_site ||= Site.from(@request_uri)
    end

    # @return [Boolean] whether the whole navigation is same-site, i.e.
    # the request site and every URI in the redirect chain are the
    # same site as the top-level site
    def same_site?
      return false unless @top_level_site
      request_site == @top_level_site &&
        redirect_chain_sites.all? { |site| site == request_site }
    end

    # @return [Boolean] the opposite of #same_site?
    def cross_site?
      !same_site?
    end

    # @return [Array<Site>]
    def redirect_chain_sites
      @redirect_chain.map { |uri| Site.from(uri) }
    end
  end
end

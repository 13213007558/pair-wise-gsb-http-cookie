# :markup: markdown

class HTTP::CookieJar
  # A store class that uses a hash-based cookie store.
  #
  # In this store, cookies that share the same name, domain and path
  # will overwrite each other regardless of the `for_domain` flag
  # value.  This store is built after the storage model described in
  # RFC 6265 5.3 where there is no mention of how the host-only-flag
  # affects in storing cookies.  On the other hand, in MozillaStore
  # two cookies with the same name, domain and path coexist as long as
  # they differ in the `for_domain` flag value, which means they need
  # to be expired individually.
  class HashStore < AbstractStore
    def default_options
      {
        :gc_threshold => HTTP::Cookie::MAX_COOKIES_TOTAL / 20
      }
    end

    # :call-seq:
    #   new(**options)
    #
    # Generates a hash based cookie store.
    #
    # Available option keywords are as below:
    #
    # :gc_threshold
    # : GC threshold; A GC happens when this many times cookies have
    # been stored (default: `HTTP::Cookie::MAX_COOKIES_TOTAL / 20`)
    def initialize(options = nil)
      super

      @jar = {
      # hostname => {
      #   path => {
      #     partition_key => {
      #       name => cookie,
      #     },
      #     ...
      #   },
      #   ...
      # },
      # ...
      }

      @gc_index = 0
    end

    # The copy constructor.  This store class supports cloning.
    def initialize_copy(other)
      @jar = Marshal.load(Marshal.dump(other.instance_variable_get(:@jar)))
    end

    def add(cookie)
      path_cookies = (@jar[cookie.domain] ||= {})[cookie.path] ||= {}
      partition_cookies = path_cookies[cookie.partition_key] ||= {}
      partition_cookies[cookie.name] = cookie
      cleanup if (@gc_index += 1) >= @gc_threshold
      self
    end

    def delete(cookie)
      paths = @jar[cookie.domain] or return self
      path_cookies = paths[cookie.path] or return self
      partition_cookies = path_cookies[cookie.partition_key] or return self
      partition_cookies.delete(cookie.name)
      self
    end

    def each(uri = nil, context = nil) # :yield: cookie
      now = Time.now
      if uri
        tpath = uri.path
        @jar.each { |domain, paths|
          paths.each { |path, hash|
            next unless HTTP::Cookie.path_match?(path, tpath)
            hash.each { |partition_key, partition_cookies|
              partition_cookies.delete_if { |name, cookie|
                if cookie.expired?(now)
                  true
                else
                  if valid_for_request?(cookie, uri, context)
                    cookie.accessed_at = now
                    yield cookie
                  end
                  false
                end
              }
            }
          }
        }
      else
        synchronize {
          @jar.each { |domain, paths|
            paths.each { |path, hash|
              hash.each { |partition_key, partition_cookies|
                partition_cookies.delete_if { |name, cookie|
                  if cookie.expired?(now)
                    true
                  else
                    yield cookie
                    false
                  end
                }
              }
            }
          }
        }
      end
      self
    end

    def clear
      @jar.clear
      self
    end

    def cleanup(session = false)
      now = Time.now
      all_cookies = []

      synchronize {
        break if @gc_index == 0

        @jar.each { |domain, paths|
          domain_cookies = []

          paths.each { |path, hash|
            hash.each { |partition_key, partition_cookies|
              partition_cookies.delete_if { |name, cookie|
                if cookie.expired?(now) || (session && cookie.session?)
                  true
                else
                  domain_cookies << cookie
                  false
                end
              }
            }
          }

          if (debt = domain_cookies.size - HTTP::Cookie::MAX_COOKIES_PER_DOMAIN) > 0
            domain_cookies.sort_by!(&:created_at)
            domain_cookies.slice!(0, debt).each { |cookie|
              delete(cookie)
            }
          end

          all_cookies.concat(domain_cookies)
        }

        if (debt = all_cookies.size - HTTP::Cookie::MAX_COOKIES_TOTAL) > 0
          all_cookies.sort_by!(&:created_at)
          all_cookies.slice!(0, debt).each { |cookie|
            delete(cookie)
          }
        end

        @jar.delete_if { |domain, paths|
          paths.delete_if { |path, hash|
            hash.delete_if { |partition_key, partition_cookies|
              partition_cookies.empty?
            }
            hash.empty?
          }
          paths.empty?
        }

        @gc_index = 0
      }
      self
    end

    private

    # Selects a cookie for a request.  With no request context the
    # legacy rule (domain, path, secure) is used.  With a context the
    # SameSite attribute and the Partitioned-cookie partition key are
    # honored as well.
    def valid_for_request?(cookie, uri, context)
      if context
        cookie.sendable_for_context?(context)
      else
        cookie.valid_for_uri?(uri)
      end
    end
  end
end

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
      partition = cookie.partitioned? ? cookie.partition_key : nil
      hashes = (@jar[cookie.domain] ||= {})[cookie.path] ||= {}
      path_cookies = hashes[partition] ||= {}
      path_cookies[cookie.name] = cookie
      cleanup if (@gc_index += 1) >= @gc_threshold
      self
    end

    def delete(cookie)
      partition = cookie.partitioned? ? cookie.partition_key : nil
      if paths = @jar[cookie.domain]
        if hashes = paths[cookie.path]
          if path_cookies = hashes[partition]
            path_cookies.delete(cookie.name)
            hashes.delete(partition) if path_cookies.empty?
            paths.delete(cookie.path) if hashes.empty?
            @jar.delete(cookie.domain) if paths.empty?
          end
        end
      end
      self
    end

    def each(uri = nil, context = nil) # :yield: cookie
      now = Time.now
      if uri
        tpath = uri.path
        wanted_partitions = context && [nil, context.top_level_site]
        @jar.each { |domain, paths|
          empty_paths = []
          paths.each { |path, hash|
            next unless HTTP::Cookie.path_match?(path, tpath)
            empty_partitions = []
            hash.each { |partition, path_cookies|
              next if wanted_partitions &&
                !wanted_partitions.include?(partition)
              expired_names = []
              path_cookies.each { |name, cookie|
                if cookie.expired?(now)
                  expired_names << name
                elsif cookie.valid_for_uri?(uri)
                  cookie.accessed_at = now
                  yield cookie
                end
              }
              expired_names.each { |name| path_cookies.delete(name) }
              empty_partitions << partition if path_cookies.empty?
            }
            empty_partitions.each { |partition| hash.delete(partition) }
            empty_paths << path if hash.empty?
          }
          empty_paths.each { |path| paths.delete(path) }
          @jar.delete(domain) if paths.empty?
        }
      else
        synchronize {
          @jar.each { |domain, paths|
            empty_paths = []
            paths.each { |path, hash|
              empty_partitions = []
              hash.each { |partition, path_cookies|
                expired_names = []
                path_cookies.each { |name, cookie|
                  if cookie.expired?(now)
                    expired_names << name
                  else
                    yield cookie
                  end
                }
                expired_names.each { |name| path_cookies.delete(name) }
                empty_partitions << partition if path_cookies.empty?
              }
              empty_partitions.each { |partition| hash.delete(partition) }
              empty_paths << path if hash.empty?
            }
            empty_paths.each { |path| paths.delete(path) }
            @jar.delete(domain) if paths.empty?
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

          empty_paths = []
          paths.each { |path, hash|
            empty_partitions = []
            hash.each { |partition, path_cookies|
              expired_names = []
              path_cookies.each { |name, cookie|
                if cookie.expired?(now) || (session && cookie.session?)
                  expired_names << name
                else
                  domain_cookies << cookie
                end
              }
              expired_names.each { |name| path_cookies.delete(name) }
              empty_partitions << partition if path_cookies.empty?
            }
            empty_partitions.each { |partition| hash.delete(partition) }
            empty_paths << path if hash.empty?
          }
          empty_paths.each { |path| paths.delete(path) }

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
            hash.empty?
          }
          paths.empty?
        }

        @gc_index = 0
      }
      self
    end
  end
end

module ::MItamae
  module Plugin
    module ResourceExecutor
      class GpgKeyring < ::MItamae::ResourceExecutor::File
        # import-minimal does not affect what gets exported (export-minimal
        # already decides that); it is here to bound the cost of importing a
        # poisoned key that carries tens of thousands of third-party
        # signatures, which makes a plain import effectively hang. Keys can
        # come from arbitrary URLs, so this is a deliberate defense, not
        # redundancy. self-sigs-only would be the precise tool but is
        # missing from older GnuPG; import-minimal (GnuPG >= 1.4.3) is the
        # portable equivalent.
        IMPORT_OPTIONS = ['--import-options', 'import-minimal'].freeze

        # --receive-keys takes its import options from --keyserver-options,
        # not from --import-options (see gpg(1) on keyserver-options:
        # "Valid import-options or export-options may be used here as well").
        KEYSERVER_IMPORT_OPTIONS = ['--keyserver-options', 'import-minimal'].freeze

        # Public keyservers fail intermittently, so network fetches are
        # retried with exponential backoff before the run gives up.
        RETRY_LIMIT = 3
        RETRY_INTERVAL = 2 # seconds, doubled after every failed attempt

        private

        @tempfile = nil

        # Runs the block until its command result succeeds, backing off
        # exponentially between attempts. Always returns the last result;
        # raising on final failure stays at the call site.
        def with_retry(subject)
          interval = RETRY_INTERVAL
          attempt = 1
          while true
            result = yield
            return result if result.exit_status == 0
            return result if attempt >= RETRY_LIMIT
            MItamae.logger.warn "#{subject} failed (attempt #{attempt}/#{RETRY_LIMIT}), retrying in #{interval} seconds..."
            sleep interval
            attempt += 1
            interval *= 2
          end
        end

        def gpg(homedir, args)
          [
            'gpg',
            '--homedir', homedir,
            '--quiet',
            '--batch',
            '--with-colons',
          ].concat(args)
        end

        # Parses `gpg --with-colons` key listing lines into one record per
        # pub key: { fingerprint:, uids:, sub_fingerprints: }. uid and sub
        # entries belong to the pub record they follow.
        def parse_colons(lines)
          records = []
          record = nil
          section = nil
          lines.each do |line|
            entry = line.strip.split(':')
            case entry[0]
            when 'pub'
              record = { fingerprint: nil, uids: [], sub_fingerprints: [] }
              records << record
              section = 'pub'
            when 'sub'
              section = 'sub'
            when 'fpr'
              case section
              when 'pub'
                record[:fingerprint] = entry[9]
              when 'sub'
                record[:sub_fingerprints] << entry[9]
              else
                raise 'unknown type'
              end
              section = nil
            when 'uid'
              # A whitelist of "valid" states would break on placed files:
              # without a trustdb every live uid lists as '-' (unknown), so
              # only the states that mark a uid as dead are excluded.
              record[:uids] << entry[9] if record && !%w[r e].include?(entry[1])
            end
          end
          records
        end

        # A fingerprint that matches a sub key is a recipe mistake worth its
        # own message: treated as a plain mismatch it would trigger an
        # endless re-fetch loop (the fetch finds the key, the export writes
        # the primary fingerprint, the next run mismatches again).
        def raise_if_sub_key_fingerprint(records, source)
          sub_owner = records.detect {|r| r[:sub_fingerprints].include?(desired.fingerprint) }
          if sub_owner
            raise "fingerprint #{desired.fingerprint} is a sub key of #{sub_owner[:fingerprint]}; specify the primary key fingerprint (#{source})"
          end
        end

        # user_id is an assertion, not a convergible attribute: a keyring
        # cannot be "fixed" into carrying the requested uid, so a mismatch
        # stops the run instead of updating the file. The match is an exact
        # string comparison against the key's valid uids.
        def verify_user_id(uids, source)
          return unless desired.user_id

          if uids.empty?
            # Only raise when user_id was requested: keys.openpgp.org
            # serves unverified keys without any user id, so an empty uid
            # set is a normal state for fingerprint-only recipes.
            raise "gpg user_id verification failed: key from #{source} has no valid user id; remove the user_id attribute if this is expected (keys.openpgp.org serves unverified keys without user ids)"
          end

          unless uids.include?(desired.user_id)
            raise "gpg user_id verification failed: expected #{desired.user_id.inspect}, key from #{source} has #{uids.inspect}"
          end
        end

        def run_action(action)
          if run_command(['which', 'gpg'], error: false).exit_status != 0
            raise "`gpg` command is not available. Please install gnupg to use mitamae's gpg_keyring."
          end

          if run_command(['which', 'curl'], error: false).exit_status != 0
            raise "`curl` command is not available. Please install curl to use mitamae's gpg_keyring."
          end

          super
        end

        def set_desired_attributes(desired, action)
          super

          desired.fingerprint = desired.fingerprint.strip.upcase.delete(' ').delete_prefix('0X')
          if desired.fingerprint.length != 40
            raise 'unknown fingerprint'
          end
          MItamae.logger.debug "fingerprint: #{desired.fingerprint}"

          if !desired.keyserver
            desired.keyserver = 'hkps://keys.openpgp.org'
          end
          MItamae.logger.debug "keyserver: #{desired.keyserver}"
        end

        def set_current_attributes(current, action)
          super

          return unless current.exist

          lines = []

          Dir.mktmpdir{|homedir|
            result = run_command(gpg(homedir, IMPORT_OPTIONS + ['--import', attributes.path]), error: false)
            if result.exit_status != 0
              raise MItamae::Backend::CommandExecutionError, "gpg import key: #{attributes.path}"
            end

            result = run_command(gpg(homedir, ['--fingerprint']), error: false)
            if result.exit_status != 0
              raise MItamae::Backend::CommandExecutionError, "gpg show fingerprint"
            end

            lines = result.stdout.lines
          }

          records = parse_colons(lines)
          if records.empty?
            raise "no key could be read from #{attributes.path} (gpg cannot import a key that has no user id packet at all)"
          end

          record = records.detect {|r| r[:fingerprint] == desired.fingerprint }
          if record
            others = records.map {|r| r[:fingerprint] } - [record[:fingerprint]]
            unless others.empty?
              # Reads tolerate foreign keys in the file; writes never touch
              # such a file (see the guard below), so their presence is
              # only surfaced for diagnosis.
              MItamae.logger.debug "keyring also contains other keys: #{others.inspect}"
            end
            current.fingerprint = record[:fingerprint]
            verify_user_id(record[:uids], attributes.path)
            # Verification proved the exact match, so mirroring the desired
            # string keeps the comparison type-safe: an Array here against
            # the desired String would report a change on every run. Without
            # user_id the comparison is skipped (the desired side is nil)
            # and the full valid uid set is the honest current state.
            current.user_id = desired.user_id ? desired.user_id : record[:uids]
          else
            raise_if_sub_key_fingerprint(records, attributes.path)

            if records.length > 1
              # A fingerprint mismatch triggers a re-fetch that rewrites the
              # whole file, which would silently drop every other key kept
              # in it. This resource only ever writes single-key files.
              raise "#{attributes.path} contains multiple keys #{records.map {|r| r[:fingerprint] }.inspect} and none is #{desired.fingerprint}; refusing to rewrite the file"
            end

            # Single foreign key: adopt it as the current state so the
            # fingerprint mismatch triggers the usual re-fetch and
            # replacement. It is about to be replaced, so the user_id
            # assertion runs against the fetched key (pre_action) instead.
            current.fingerprint = records[0][:fingerprint]
            current.user_id = records[0][:uids].last
          end
          MItamae.logger.debug "fingerprint: #{current.fingerprint}"
        end

        def content_file
          @tempfile
        end

        def pre_action
          Dir.mktmpdir{|homedir|
            if (!desired.content and !current.exist) or current.fingerprint != desired.fingerprint
              if desired.url
                MItamae.logger.debug "gpg download url: #{desired.url}"

                result = with_retry("gpg download key: url: #{desired.url}") {
                  run_command(['curl', '-fsSL', '-o', "/tmp/#{desired.fingerprint}", desired.url], error: false)
                }
                if result.exit_status != 0
                  raise MItamae::Backend::CommandExecutionError, "gpg download key: url: #{desired.url}"
                end

                result = run_command(gpg(homedir, IMPORT_OPTIONS + ['--import', "/tmp/#{desired.fingerprint}"]), error: false)
                if result.exit_status != 0
                  raise MItamae::Backend::CommandExecutionError, "gpg import key: fingerprint: #{desired.fingerprint}"
                end
              else
                MItamae.logger.debug "gpg download keyserver: #{desired.keyserver}"

                File.open(File.join(homedir, 'gpg.conf'), 'w') do |f|
                  f.write("keyserver #{desired.keyserver}")
                end

                result = with_retry("gpg receive key: keyserver: #{desired.keyserver}") {
                  run_command(gpg(homedir, KEYSERVER_IMPORT_OPTIONS + ['--receive-keys', desired.fingerprint]), error: false)
                }
                if result.exit_status != 0
                  raise MItamae::Backend::CommandExecutionError, "gpg receive key: keyserver: #{desired.keyserver} fingerprint: #{desired.fingerprint}"
                end
              end

              result = run_command(gpg(homedir, ['--fingerprint']), error: false)
              if result.exit_status != 0
                raise MItamae::Backend::CommandExecutionError, 'gpg list fetched keys'
              end

              # Verify the fetched key before the export: a key that is not
              # what the recipe claims must never reach the target file.
              records = parse_colons(result.stdout.lines)
              source = desired.url ? desired.url : desired.keyserver
              record = records.detect {|r| r[:fingerprint] == desired.fingerprint }
              if record.nil?
                raise_if_sub_key_fingerprint(records, source)
                raise "gpg fetched key does not contain fingerprint #{desired.fingerprint}: got #{records.map {|r| r[:fingerprint] }.inspect} (#{source})"
              end
              verify_user_id(record[:uids], source)

              # export-minimal drops third-party signatures, so the placed
              # file stays deterministic no matter what the source attached
              # to the key (keyservers since GnuPG 2.2.17 already strip them
              # on receive, older ones do not). Revocation signatures are
              # self-signatures and survive this.
              if File.extname(attributes.path).eql?('.gpg')
                opts = ['--export-options', 'export-minimal', '--export', desired.fingerprint]
              else
                opts = ['--export-options', 'export-minimal', '--export', '--armor', desired.fingerprint]
              end

              result = run_command(gpg(homedir, opts), error: false)
              if result.exit_status != 0
                raise MItamae::Backend::CommandExecutionError, "gpg export key: fingerprint: #{desired.fingerprint}"
              end

              Dir.mkdir(File.join(homedir, 'download'), 0755)
              File.open(File.join(homedir, 'download', desired.fingerprint), 'w') do |f|
                f.write(result.stdout)
              end
              @tempfile = File.join(homedir, 'download', desired.fingerprint)
            end

            super
          }
        end
      end
    end
  end
end

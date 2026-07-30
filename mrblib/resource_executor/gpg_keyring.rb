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

        # --recv-keys takes its import options from --keyserver-options,
        # not from --import-options (see gpg(1) on keyserver-options:
        # "Valid import-options or export-options may be used here as well").
        KEYSERVER_IMPORT_OPTIONS = ['--keyserver-options', 'import-minimal'].freeze

        # Options for every key listing, shaped by what GnuPG versions
        # older than 2.1.15 need. Both are no-ops on newer ones, so the
        # listing is identical everywhere and only has to be parsed once.
        #
        # --fixed-list-mode keeps the primary uid in a uid record of its
        # own. Without it GnuPG 1.4 inlines that uid into the pub record
        # and emits no uid record for it at all, which reads here as a key
        # with no valid uid and breaks the user_id assertion. GnuPG 2.x is
        # always in fixed list mode; the option exists since 1.0.5.
        #
        # --fingerprint repeated adds the fpr records for sub keys. From
        # 2.1.15 on they are unconditional ("gpg: Always print fingerprint
        # records in --with-colons mode"); before that they are printed
        # only when the option is given twice, leaving the sub key check
        # with nothing to match.
        LIST_OPTIONS = ['--fixed-list-mode', '--fingerprint', '--fingerprint'].freeze

        # Oldest GnuPG this resource works with: import-minimal and
        # export-minimal, which every fetch depends on, arrived in 1.4.3.
        # Listings are already normalized across the whole range by
        # LIST_OPTIONS, so this is the only version that has to be named.
        MINIMUM_GPG_VERSION = '1.4.3'.freeze

        # Public key algorithms that need ECC support in gpg (RFC 6637
        # and RFC 8032 assignments). GnuPG carries none of them before
        # 2.1, which is what makes them worth naming: 1.4 rejects such a
        # key with "no valid user IDs", because it cannot check a
        # self-signature it has no algorithm for, and that message sends
        # everyone looking at the uids instead of the algorithm.
        ECC_PUBKEY_ALGORITHMS = {
          18 => 'ECDH',
          19 => 'ECDSA',
          22 => 'EdDSA',
        }.freeze

        # Algorithm names as `gpg --version` lists them. The names are
        # printed verbatim while the labels around them are translated,
        # so the whole output is searched rather than a "Pubkey:" line.
        ECC_ALGORITHM_NAMES = %w[ECDH ECDSA EDDSA].freeze

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

        # Compares dotted version strings numerically, so that 1.4.23 is
        # newer than 1.4.3 (a plain string compare gets that wrong).
        def version_at_least?(actual, minimum)
          actual_parts = actual.split('.').map {|part| part.to_i }
          minimum_parts = minimum.split('.').map {|part| part.to_i }
          minimum_parts.length.times do |i|
            current = actual_parts[i] ? actual_parts[i] : 0
            required = minimum_parts[i]
            return true if current > required
            return false if current < required
          end
          true
        end

        # Checked up front so an ancient gpg is named as such, instead of
        # failing later as an unknown-option error from inside a fetch.
        def verify_gpg_version
          result = run_command(['gpg', '--version'], error: false)
          # Anchored to GnuPG's own banner ("gpg (GnuPG) 2.4.4", or
          # "gpg (GnuPG/MacGPG2) 2.2.41" once repackaged) rather than to
          # the first number on the first line: a wrapper that announces
          # itself first would otherwise have its own version read as
          # gpg's and get a perfectly good binary refused.
          match = result.exit_status == 0 ? /\(GnuPG[^)]*\)\s+(\d+\.\d+(\.\d+)?)/.match(result.stdout) : nil

          if match.nil?
            # A build that prints no recognizable banner is left alone.
            # Refusing to run on a version that cannot be read would be
            # worse than letting the actual gpg invocations speak for
            # themselves.
            MItamae.logger.debug 'could not read the gpg version, skipping the minimum version check'
            return
          end

          version = match[1]

          MItamae.logger.debug "gpg version: #{version}"
          return if version_at_least?(version, MINIMUM_GPG_VERSION)

          raise "`gpg` is #{version}, but mitamae's gpg_keyring needs GnuPG #{MINIMUM_GPG_VERSION} or newer (--import-options import-minimal)."
        end

        # Whether the gpg in use carries ECC at all. Read from its own
        # algorithm list, so a build without ECC support is recognized
        # even on a version new enough to have it.
        def gpg_supports_ecc?
          if @gpg_supports_ecc.nil?
            result = run_command(['gpg', '--version'], error: false)
            # Unreadable output must not turn into a claim about the
            # binary, so assume support and stay quiet.
            @gpg_supports_ecc = result.exit_status != 0 ||
                                ECC_ALGORITHM_NAMES.any? {|name| result.stdout.include?(name) }
          end
          @gpg_supports_ecc
        end

        # Reads the primary key's algorithm out of gpg's packet dump.
        # Parsing output is usually a trap, but these dump lines are
        # written with a plain fprintf in gpg (no translation), so the
        # number can be read whatever the locale is. Returns nil unless
        # the key turns out to be one this gpg cannot handle.
        def unsupported_algorithm(path)
          return nil if gpg_supports_ecc?

          result = run_command(['gpg', '--list-packets', path], error: false)
          return nil if result.exit_status != 0

          line = result.stdout.lines.detect {|l| l.include?(':public key packet:') }
          # The algorithm sits on the line after the packet header.
          index = line ? result.stdout.lines.index(line) : nil
          match = index ? /algo (\d+)/.match(result.stdout.lines[index + 1].to_s) : nil
          return nil if match.nil?

          name = ECC_PUBKEY_ALGORITHMS[match[1].to_i]
          name ? "public key algorithm #{match[1]} (#{name})" : nil
        end

        # The receive path never gets a file of its own to inspect - the
        # key fails inside gpg - so the gap can only be pointed at, not
        # proven. Worth saying anyway: on a binary without ECC support it
        # is the likeliest reason a receive fails.
        def missing_ecc_note
          return '' if gpg_supports_ecc?

          ' (note: the gpg in use has no ECC support, so an ECC key cannot be received by it)'
        end

        # mitamae rescues Backend::CommandExecutionError and logs only
        # "<resource> Failed.", dropping the message with it, so a
        # failure that has something to explain is raised as a plain
        # error - which mitamae does print - while the ones with nothing
        # to add keep the original type.
        def raise_command_failure(subject, note)
          raise "#{subject}#{note}" unless note.empty?

          raise MItamae::Backend::CommandExecutionError, subject
        end

        # Appended to an import failure so the cause is named instead of
        # left to gpg's misleading uid complaint.
        def unsupported_algorithm_note(path)
          algorithm = unsupported_algorithm(path)
          return '' if algorithm.nil?

          ": the key uses #{algorithm}, which the gpg in use does not support (GnuPG 2.1 or newer is required for ECC keys)"
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

        # gpg escapes ':' and '\' (and control characters) in colon-format
        # field values as C-style \xNN sequences (see gnupg doc/DETAILS).
        # Without decoding, a uid like "Colon: User" is stored as
        # "Colon\x3a User" and can never exact-match the natural string
        # given in the user_id attribute.
        def unescape_colons(value)
          value.gsub(/\\x[0-9a-fA-F]{2}/) { |match| match[2, 2].to_i(16).chr }
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
              record[:uids] << unescape_colons(entry[9]) if record && !%w[r e].include?(entry[1])
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

          verify_gpg_version

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

          # Deletion only cares whether the file exists: reading and
          # asserting the key here would just block removing an obsolete
          # keyring (e.g. one whose asserted uid has since been revoked).
          return if action == :delete

          return unless current.exist

          lines = []

          Dir.mktmpdir{|homedir|
            result = run_command(gpg(homedir, IMPORT_OPTIONS + ['--import', attributes.path]), error: false)
            if result.exit_status != 0
              raise_command_failure("gpg import key: #{attributes.path}", unsupported_algorithm_note(attributes.path))
            end

            result = run_command(gpg(homedir, LIST_OPTIONS), error: false)
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
            # desired.exist is false for the delete action: nothing to
            # fetch when the file is being removed.
            if desired.exist and ((!desired.content and !current.exist) or current.fingerprint != desired.fingerprint)
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
                  raise_command_failure("gpg import key: fingerprint: #{desired.fingerprint}", unsupported_algorithm_note("/tmp/#{desired.fingerprint}"))
                end
              else
                MItamae.logger.debug "gpg download keyserver: #{desired.keyserver}"

                File.open(File.join(homedir, 'gpg.conf'), 'w') do |f|
                  f.write("keyserver #{desired.keyserver}")
                end

                # --recv-keys, not its --receive-keys alias: GnuPG 1.4
                # only knows the short spelling, 2.x knows both.
                result = with_retry("gpg receive key: keyserver: #{desired.keyserver}") {
                  run_command(gpg(homedir, KEYSERVER_IMPORT_OPTIONS + ['--recv-keys', desired.fingerprint]), error: false)
                }
                if result.exit_status != 0
                  raise_command_failure("gpg receive key: keyserver: #{desired.keyserver} fingerprint: #{desired.fingerprint}", missing_ecc_note)
                end
              end

              result = run_command(gpg(homedir, LIST_OPTIONS), error: false)
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

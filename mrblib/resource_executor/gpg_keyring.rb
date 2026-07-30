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

          # TODO: multiple pub/sub keys
          if records.length == 1
            current.fingerprint = records[0][:fingerprint]
          else
            raise 'multiple pub keys'
          end
          current.user_id = records[0][:uids].last
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

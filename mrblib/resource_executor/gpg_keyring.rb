module ::MItamae
  module Plugin
    module ResourceExecutor
      class GpgKeyring < ::MItamae::ResourceExecutor::File
        private

        @tempfile = nil

        def gpg(homedir, args)
          [
            'gpg',
            '--homedir', homedir,
            '--quiet',
            '--batch',
            '--with-colons',
          ].concat(args)
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
            result = run_command(gpg(homedir, ['--import', attributes.path]), error: false)
            if result.exit_status != 0
              raise MItamae::Backend::CommandExecutionError, "gpg import key: #{attributes.path}"
            end

            result = run_command(gpg(homedir, ['--fingerprint']), error: false)
            if result.exit_status != 0
              raise MItamae::Backend::CommandExecutionError, "gpg show fingerprint"
            end

            lines = result.stdout.lines
          }

          before = nil
          pub_fprs = []
          sub_fprs = []
          lines.each do |line|
            entry = line.strip.split(':')
            case entry[0]
            when 'tru'
              # nothing...
            when 'uid'
              current.user_id = entry[9]
            when 'pub', 'sub'
              before = entry[0]
            when 'fpr'
              case before
              when 'pub'
                pub_fprs << entry[9]
              when 'sub'
                sub_fprs << entry[9]
              else
                raise 'unknown type'
              end
              before = nil
            end
          end

          # TODO: multiple pub/sub keys
          if pub_fprs.length == 1
            current.fingerprint = pub_fprs[0]
          else
            raise 'multiple pub keys'
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

                result = run_command(['curl', '-fsSL', '-o', "/tmp/#{desired.fingerprint}", desired.url], error: false)
                if result.exit_status != 0
                  raise MItamae::Backend::CommandExecutionError, "gpg download key: url: #{desired.url}"
                end

                result = run_command(gpg(homedir, ['--import', "/tmp/#{desired.fingerprint}"]), error: false)
                if result.exit_status != 0
                  raise MItamae::Backend::CommandExecutionError, "gpg import key: fingerprint: #{desired.fingerprint}"
                end
              else
                MItamae.logger.debug "gpg download keyserver: #{desired.keyserver}"

                File.open(File.join(homedir, 'gpg.conf'), 'w') do |f|
                  f.write("keyserver #{desired.keyserver}")
                end

                result = run_command(gpg(homedir, ['--receive-keys', desired.fingerprint]), error: false)
                if result.exit_status != 0
                  raise MItamae::Backend::CommandExecutionError, "gpg receive key: keyserver: #{desired.keyserver} fingerprint: #{desired.fingerprint}"
                end
              end

              if File.extname(attributes.path).eql?('.gpg')
                opts = ['--export', desired.fingerprint]
              else
                opts = ['--export', '--armor', desired.fingerprint]
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

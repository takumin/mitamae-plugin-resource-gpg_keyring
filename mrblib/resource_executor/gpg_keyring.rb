module ::MItamae
  module Plugin
    module ResourceExecutor
      class GpgKeyring < ::MItamae::ResourceExecutor::File
        private

        @homedir = ''
        @tempfile = nil

        def gpg(args)
          [
            'gpg',
            '--homedir', @homedir,
            '--quiet',
            '--batch',
            '--with-colons',
          ].concat(args)
        end

        def run_action(action)
          if run_command(['which', 'gpg'], error: false).exit_status != 0
            raise "`gpg` command is not available. Please install gnupg to use mitamae's gpg_keyring."
          end

          @homedir = Dir.mktmpdir
          run_command(gpg(['--list-keys']))

          super

          run_specinfra(:remove_file, @homedir)
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

          result = run_command(gpg(['--import', attributes.path]), error: false)
          if result.exit_status != 0
            raise MItamae::Backend::CommandExecutionError, "gpg import key: #{attributes.path}"
          end

          result = run_command(gpg(['--fingerprint']), error: false)
          if result.exit_status != 0
            raise MItamae::Backend::CommandExecutionError, "gpg show fingerprint"
          end

          before = nil
          pub_fprs = []
          sub_fprs = []
          result.stdout.lines.each do |line|
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

        def pre_action
          if !current.exist or current.fingerprint != desired.fingerprint
            if desired.url
              content = download_url(desired.url)
            elsif desired.keyserver
              content = download_keyserver(desired.keyserver, desired.fingerprint)
            end

            Dir.mkdir(File.join(@homedir, 'download'), 0755)
            File.open(File.join(@homedir, 'download', desired.fingerprint), 'w') do |f|
              f.write(content)
            end
            @tempfile = File.join(@homedir, 'download', desired.fingerprint)
          end

          super
        end

        def content_file
          @tempfile
        end

        def download_url(url)
          MItamae.logger.debug "gpg download url: #{url}"

          if run_command(['which', 'curl'], error: false).exit_status != 0
            raise "`curl` command is not available. Please install curl to use mitamae's gpg_keyring."
          end

          result = run_command(['curl', '-fsSL', url], error: false)
          if result.exit_status != 0
            raise MItamae::Backend::CommandExecutionError, "gpg download key: url: #{url}"
          end

          result.stdout
        end

        def download_keyserver(keyserver, fingerprint)
          MItamae.logger.debug "gpg download keyserver: #{keyserver} fingerprint: #{fingerprint}"

          File.open(File.join(@homedir, 'gpg.conf'), 'w') do |f|
            f.write("keyserver #{keyserver}")
          end

          result = run_command(gpg(['--receive-keys', fingerprint]), error: false)
          if result.exit_status != 0
            raise MItamae::Backend::CommandExecutionError, "gpg download key: keyserver: #{keyserver} fingerprint: #{fingerprint}"
          end

          result = run_command(gpg(['--export', '--armor', fingerprint]), error: false)
          if result.exit_status != 0
            raise MItamae::Backend::CommandExecutionError, "gpg export key: keyserver: #{keyserver} fingerprint: #{fingerprint}"
          end

          result.stdout
        end
      end
    end
  end
end

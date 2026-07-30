require 'fileutils'
require 'open3'
require 'tmpdir'

# Maintainer tool: (re)generates the committed key fixtures in
# test/fixture/. The suite itself never generates keys - it only reads
# the committed files - so this task runs rarely, by hand.
#
# Keys are ed25519 with expiry 'never' on purpose: committed fixtures
# must not rot with time. Keep it that way.
#
# Regenerating changes the fingerprints, which are written literally
# into test/recipe/ and spec/, so update those together (the task
# prints the new values). Pass fixture names to regenerate a subset:
#
#   rake 'fixtures:regenerate[with-subkey.asc]'
#
# The GnuPG homedir lives in Dir.mktmpdir, not inside the repository:
# gpg-agent sockets are limited to ~108 path bytes and in-repo paths on
# deep checkouts exceed that.
class GpgFixture
  def self.build
    Dir.mktmpdir do |homedir|
      FileUtils.chmod(0o700, homedir)
      fixture = new(homedir)
      begin
        yield fixture
      ensure
        fixture.kill_agent
      end
    end
  end

  def initialize(homedir)
    @homedir = homedir
  end

  def generate_key(uid)
    gpg('--quick-generate-key', uid, 'ed25519', 'cert', 'never')
    fingerprint_of(uid)
  end

  def add_uid(fingerprint, uid)
    gpg('--quick-add-uid', fingerprint, uid)
  end

  def revoke_uid(fingerprint, uid)
    gpg('--yes', '--quick-revoke-uid', fingerprint, uid)
  end

  def add_key(fingerprint, algo = 'cv25519', usage = 'encr')
    gpg('--quick-add-key', fingerprint, algo, usage, 'never')
  end

  def sign_key(signer_fingerprint, target_fingerprint)
    gpg('--yes', '--local-user', signer_fingerprint, '--quick-sign-key', target_fingerprint)
  end

  # Writes an armored export of the given key(s). Extra options (e.g.
  # --export-filter ...) are placed before --export.
  def export(fingerprints, to:, options: [])
    File.write(to, gpg(*options, '--armor', '--export', *Array(fingerprints)))
  end

  def fingerprint_of(uid)
    gpg('--with-colons', '--list-keys', uid)[/^fpr:{9}([0-9A-F]{40}):/, 1]
  end

  def sub_fingerprint_of(uid)
    gpg('--with-colons', '--list-keys', uid).scan(/^fpr:{9}([0-9A-F]{40}):/).flatten[1]
  end

  def kill_agent
    Open3.capture2e('gpgconf', '--homedir', @homedir, '--kill', 'gpg-agent')
  end

  private

  def gpg(*args)
    command = [
      'gpg', '--homedir', @homedir, '--batch',
      '--pinentry-mode', 'loopback', '--passphrase', '', *args
    ]
    stdout, stderr, status = Open3.capture3(*command)
    raise "#{command.join(' ')} failed:\n#{stderr}" unless status.success?

    stdout
  end
end

FIXTURE_DIR = File.expand_path('../test/fixture', __dir__)

FIXTURES = {
  # A plain single-uid key: existing-keyring cases and download source.
  'valid-key.asc' => lambda do |gpg, path|
    key = gpg.generate_key('Valid <valid@example.com>')
    gpg.export(key, to: path)
    key
  end,

  # A key carrying a third-party signature next to its self-signature.
  'third-party-signed.asc' => lambda do |gpg, path|
    target = gpg.generate_key('Target Key <target@example.com>')
    third_party = gpg.generate_key('Third Party <third@example.com>')
    gpg.sign_key(third_party, target)
    gpg.export(target, to: path)
    target
  end,

}

namespace :fixtures do
  desc 'Regenerate committed key fixtures in test/fixture/ (all, or only the names given as task args)'
  task :regenerate do |_task, args|
    names = args.extras.empty? ? FIXTURES.keys : args.extras
    unknown = names - FIXTURES.keys
    raise "unknown fixture(s): #{unknown.join(', ')}" unless unknown.empty?

    FileUtils.mkdir_p(FIXTURE_DIR)
    names.each do |name|
      path = File.join(FIXTURE_DIR, name)
      fingerprint = GpgFixture.build { |gpg| FIXTURES[name].call(gpg, path) }
      puts format('%-24s %s', name, fingerprint)
    end
    puts 'Update the fingerprints written literally in test/recipe/ and spec/.'
  end
end

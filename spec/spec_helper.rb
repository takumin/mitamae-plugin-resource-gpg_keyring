require 'digest'
require 'fileutils'
require 'open-uri'
require 'open3'
require 'rbconfig'

module GpgKeyringSpecHelper
  ROOT_DIR = File.expand_path('..', __dir__)
  TEST_DIR = File.join(ROOT_DIR, 'test')
  TEMPORARY_DIR = File.join(TEST_DIR, 'temporary')
  BIN_DIR = File.join(ROOT_DIR, '.bin')

  MITAMAE_VERSION = ENV.fetch('MITAMAE_VERSION', 'v2.0.2')
  MITAMAE_RELEASE_URL = "https://github.com/itamae-kitchen/mitamae/releases/download/#{MITAMAE_VERSION}"

  # Fixed address of the local fixture/HKP server (see
  # spec/support/local_server.rb); recipes reference it literally.
  LOCAL_SERVER_HOST = '127.0.0.1'
  LOCAL_SERVER_PORT = 39_418

  MitamaeRun = Struct.new(:log, :status) do
    def success?
      status.success?
    end
  end

  module_function

  # --- mitamae binary -----------------------------------------------------

  def mitamae_bin
    @mitamae_bin ||= resolve_mitamae
  end

  def resolve_mitamae
    explicit = ENV['MITAMAE']
    return explicit if explicit

    on_path = which('mitamae')
    return on_path if on_path

    fetch_mitamae
  end

  def which(command)
    ENV.fetch('PATH', '').split(File::PATH_SEPARATOR).each do |dir|
      candidate = File.join(dir, command)
      return candidate if File.file?(candidate) && File.executable?(candidate)
    end
    nil
  end

  # Downloads a pinned mitamae release into .bin/ and verifies it against
  # the SHA256SUMS published with the same release.
  def fetch_mitamae
    os = RbConfig::CONFIG['host_os'].include?('darwin') ? 'darwin' : 'linux'
    arch = RbConfig::CONFIG['host_cpu']
    arch = 'aarch64' if arch == 'arm64'
    asset = "mitamae-#{arch}-#{os}"
    dest = File.join(BIN_DIR, "#{asset}-#{MITAMAE_VERSION}")
    return dest if File.executable?(dest)

    warn "downloading #{asset} #{MITAMAE_VERSION} from GitHub Releases..."
    binary = URI.open("#{MITAMAE_RELEASE_URL}/#{asset}", 'rb', &:read)
    sums = URI.open("#{MITAMAE_RELEASE_URL}/SHA256SUMS", 'rb', &:read)
    expected = sums.lines.map(&:split).find { |(_, name)| name == asset }&.first
    actual = Digest::SHA256.hexdigest(binary)
    if expected.nil? || expected != actual
      raise "checksum mismatch for #{asset}: expected #{expected.inspect}, got #{actual}"
    end

    FileUtils.mkdir_p(BIN_DIR)
    File.binwrite(dest, binary)
    FileUtils.chmod(0o755, dest)
    dest
  end

  # Exposes this plugin to `mitamae local --plugins=.plugins`.
  def ensure_plugins
    plugins_dir = File.join(ROOT_DIR, '.plugins')
    return if File.exist?(plugins_dir)

    FileUtils.mkdir_p(plugins_dir)
    File.symlink('..', File.join(plugins_dir, File.basename(ROOT_DIR)))
  end

  # --- legacy GnuPG -------------------------------------------------------

  # LEGACY_GPG=/usr/bin/gpg1 runs the whole suite against an old GnuPG.
  # The resource always calls plain `gpg`, so the binary is swapped by
  # putting a shim directory in front of mitamae's PATH; the inspection
  # helpers below keep calling the modern gpg from this process' own PATH,
  # which is what makes examples verifiable at all (GnuPG 1.4 has no
  # --show-keys). The committed fixtures are RSA so that a legacy run has
  # keys it can read - only the ed25519 example opts out.
  def legacy_gpg?
    !ENV['LEGACY_GPG'].nil?
  end

  def legacy_shim_dir
    @legacy_shim_dir ||= begin
      dir = File.join(BIN_DIR, 'legacy-shim')
      FileUtils.mkdir_p(dir)
      shim = File.join(dir, 'gpg')
      FileUtils.rm_f(shim)
      FileUtils.ln_s(File.expand_path(ENV.fetch('LEGACY_GPG')), shim)
      dir
    end
  end

  # The gpg under test, before any shim is put in front of it.
  def real_gpg
    ENV['LEGACY_GPG'] || which('gpg')
  end

  # Puts a throwaway `gpg` in front of mitamae for the duration of the
  # block, answering --version with the given shell snippet and handing
  # every other call to the real binary. Banners no real gpg prints are
  # the only way to drive the version check from a spec.
  def with_gpg_stub(version_branch)
    dir = File.join(BIN_DIR, 'gpg-stub')
    FileUtils.mkdir_p(dir)
    stub = File.join(dir, 'gpg')
    File.write(stub, <<~SCRIPT)
      #!/bin/sh
      if [ "$1" = "--version" ]; then
        #{version_branch}
        exit 0
      fi
      exec #{real_gpg} "$@"
    SCRIPT
    FileUtils.chmod(0o755, stub)
    @gpg_stub_dir = dir
    yield
  ensure
    @gpg_stub_dir = nil
    FileUtils.rm_rf(dir)
  end

  def mitamae_env
    dirs = []
    dirs << @gpg_stub_dir if @gpg_stub_dir
    dirs << legacy_shim_dir if legacy_gpg?
    return {} if dirs.empty?

    { 'PATH' => (dirs + [ENV.fetch('PATH', '')]).join(File::PATH_SEPARATOR) }
  end

  # --- running mitamae ----------------------------------------------------

  def recipe_path(name)
    File.join(TEST_DIR, 'recipe', "#{name}.rb")
  end

  def run_mitamae(recipe_name)
    log, status = Open3.capture2e(
      mitamae_env, mitamae_bin, 'local', '--log-level=debug', '--plugins=.plugins',
      recipe_path(recipe_name), chdir: ROOT_DIR
    )
    MitamaeRun.new(log, status)
  end

  def expect_mitamae_success(run)
    expect(run.success?).to be(true), "mitamae exited with #{run.status.exitstatus}:\n#{run.log}"
  end

  def expect_mitamae_failure(run, pattern)
    expect(run.success?).to be(false), "expected mitamae to fail, but it exited with 0:\n#{run.log}"
    expect(run.log).to match(pattern), "expected the log to match #{pattern.inspect}:\n#{run.log}"
  end

  # --- files and gpg inspection -------------------------------------------

  def temporary(name)
    File.join(TEMPORARY_DIR, name)
  end

  def fixture(name)
    File.join(TEST_DIR, 'fixture', name)
  end

  def wipe_temporary
    FileUtils.mkdir_p(TEMPORARY_DIR)
    Dir.children(TEMPORARY_DIR).each do |entry|
      FileUtils.rm_rf(File.join(TEMPORARY_DIR, entry)) unless entry == '.gitkeep'
    end
  end

  def gpg_show_keys(path)
    log, status = Open3.capture2e('gpg', '--quiet', '--batch', '--with-colons', '--show-keys', path)
    raise "gpg --show-keys #{path} failed:\n#{log}" unless status.success?

    log
  end

  def fingerprint_of(path)
    gpg_show_keys(path)[/^fpr:{9}([0-9A-F]{40}):/, 1]
  end

  def armored?(path)
    File.binread(path).include?('BEGIN PGP PUBLIC KEY BLOCK')
  end

  def signature_packet_count(path)
    log, status = Open3.capture2e('gpg', '--list-packets', path)
    raise "gpg --list-packets #{path} failed:\n#{log}" unless status.success?

    log.scan(':signature packet:').size
  end
end

Dir[File.join(__dir__, 'support', '**', '*.rb')].sort.each { |file| require file }

RSpec.configure do |config|
  config.include GpgKeyringSpecHelper

  config.before(:suite) do
    GpgKeyringSpecHelper.ensure_plugins
    GpgKeyringSpecHelper.mitamae_bin
    if GpgKeyringSpecHelper.legacy_gpg?
      warn "gpg under test: #{`#{ENV.fetch('LEGACY_GPG')} --version`.lines.first}"
    end
    $local_key_server = LocalKeyServer.new(
      GpgKeyringSpecHelper::LOCAL_SERVER_HOST,
      GpgKeyringSpecHelper::LOCAL_SERVER_PORT,
      File.join(GpgKeyringSpecHelper::TEST_DIR, 'fixture')
    )
    $local_key_server.start
  end

  config.after(:suite) do
    $local_key_server&.stop
  end

  config.before do
    wipe_temporary
  end
end

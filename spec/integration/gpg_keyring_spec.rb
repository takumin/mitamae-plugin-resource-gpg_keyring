RSpec.describe 'gpg_keyring' do
  VALID_KEY_FINGERPRINT = 'EB7799FC07E9E5BEF41905894072ADEA8961DFD8'.freeze

  describe 'existing keyring' do
    {
      'existing_keyring' => 'uppercase fingerprint',
      'fingerprint_lowercase' => 'lowercase fingerprint',
      'fingerprint_0x_prefix' => '0x-prefixed fingerprint',
      'fingerprint_pgpdump_spaces' => 'pgpdump-style spaced fingerprint',
    }.each do |recipe, variant|
      it "leaves the existing keyring untouched (#{variant})" do
        keyring = temporary('existing.gpg.asc')
        FileUtils.cp(fixture('valid-key.asc'), keyring)

        run = run_mitamae(recipe)
        expect_mitamae_success(run)
        expect(File.binread(keyring)).to eq(File.binread(fixture('valid-key.asc')))
      end
    end
  end

  describe 'url download via file://' do
    it 'places the key through the whole fetch pipeline offline' do
      run = run_mitamae('url_download_file_scheme')
      expect_mitamae_success(run)

      keyring = temporary('file-url.gpg.asc')
      expect(armored?(keyring)).to be(true)
      expect(fingerprint_of(keyring)).to eq(VALID_KEY_FINGERPRINT)
    end
  end

  # Both fetch paths run against the local fixture server (see
  # spec/support/local_server.rb), so they need no network access.
  describe 'url download' do
    it 'places an armored keyring for an .asc target' do
      run = run_mitamae('url_download_armored')
      expect_mitamae_success(run)

      keyring = temporary('url-download.gpg.asc')
      expect(armored?(keyring)).to be(true)
      expect(fingerprint_of(keyring)).to eq(VALID_KEY_FINGERPRINT)
    end

    it 'places a binary keyring for a .gpg target' do
      run = run_mitamae('url_download_binary')
      expect_mitamae_success(run)

      keyring = temporary('url-download.gpg')
      expect(armored?(keyring)).to be(false)
      expect(fingerprint_of(keyring)).to eq(VALID_KEY_FINGERPRINT)
    end
  end

  describe 'ed25519 key' do
    it 'places an ECC key through the whole fetch pipeline' do
      skip 'GnuPG 1.4 has no ECC support' if legacy_gpg?

      run = run_mitamae('ed25519_key')
      expect_mitamae_success(run)

      keyring = temporary('ed25519.gpg')
      expect(armored?(keyring)).to be(false)
      expect(fingerprint_of(keyring)).to eq('177ACBBF0F0DF7E60E58ACD618DE04FD1CEFC6E4')
    end

    # gpg answers an ECC key it cannot parse with "no valid user IDs",
    # which is about the one thing that is not wrong with the key.
    it 'names the algorithm when the gpg in use cannot handle it' do
      skip 'the gpg under test supports ECC' unless legacy_gpg?

      run = run_mitamae('ed25519_key')
      expect_mitamae_failure(run, /public key algorithm 22 \(EdDSA\), which the gpg in use does not support/)
      expect(File.exist?(temporary('ed25519.gpg'))).to be(false)
    end

    it 'names the algorithm for an already-placed ECC keyring' do
      skip 'the gpg under test supports ECC' unless legacy_gpg?

      keyring = temporary('existing-ed25519.gpg')
      FileUtils.cp(fixture('ed25519.asc'), keyring)

      run = run_mitamae('existing_ed25519')
      expect_mitamae_failure(run, /public key algorithm 22 \(EdDSA\), which the gpg in use does not support/)
      expect(File.binread(keyring)).to eq(File.binread(fixture('ed25519.asc')))
    end
  end

  describe 'keyserver receive' do
    it 'receives the key by fingerprint over hkp' do
      run = run_mitamae('keyserver_receive')
      expect_mitamae_success(run)
      expect(fingerprint_of(temporary('keyserver.gpg.asc'))).to eq(VALID_KEY_FINGERPRINT)
    end
  end

  describe 'fingerprint validation' do
    it 'aborts when the fingerprint does not normalize to 40 hex digits' do
      run = run_mitamae('invalid_fingerprint')
      expect_mitamae_failure(run, /unknown fingerprint/)
      expect(File.exist?(temporary('never-created.gpg.asc'))).to be(false)
    end
  end
end

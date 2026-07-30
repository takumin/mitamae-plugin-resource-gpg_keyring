RSpec.describe 'gpg_keyring' do
  VALID_KEY_FINGERPRINT = '789ACEE7FE33FEACDF042B8BC0A90B87712D6C7F'.freeze

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
